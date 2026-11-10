package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	errSecureDownloadTooLarge    = errors.New("下载体积超过安全上限")
	errSecureDownloadBadHash     = errors.New("下载文件 sha256 校验失败")
	errSecureDownloadBadSize     = errors.New("下载文件实际体积与声明不符")
	errSecureDownloadStatus      = errors.New("下载返回了非成功状态码")
	errSecureDownloadNoLimit     = errors.New("安全下载必须指定正的体积上限")
	errSecureDownloadBadRedirect = errors.New("下载重定向链被安全策略拒绝")
	errSecureDownloadBadName     = errors.New("服务器给出的下载文件名不可安全落盘")
)

const (
	secureDownloadDefaultAttempts = 3
	secureDownloadBufSize         = 64 * 1024
	secureDownloadBackoffBase     = 500 * time.Millisecond
)

type secureDownloadOptions struct {
	MaxBytes       int64                       // 必填：声明与实际体积的共同硬上限
	ExpectedSHA256 string                      // 可空：非空时必须与流式摘要一致（小写十六进制）
	Attempts       int                         // 可空：<=0 时取 secureDownloadDefaultAttempts
	UserAgent      string                      // 可空：为空则不覆盖
	Client         *http.Client                // 可空：为空用 safeHTTPClient()
	Progress       func(received, total int64) // 可空：每读到一批数据回调一次
	MarkWebOrigin  bool                        // 可空：Windows 上落盘后写入 MOTW（ZoneId=3 Internet）
	ReferrerURL    string                      // 可空：MOTW 的 ReferrerUrl
}
type secureDownloadResult struct {
	Bytes      int64  // 实际落盘字节数
	SHA256     string // 实际流式 sha256（小写十六进制）
	Attempts   int    // 实际使用的尝试次数（1 表示首次成功）
	ServerName string // 可空：Content-Disposition 里通过安全校验的文件名
}

func secureDownloadCheckRedirect(req *http.Request, via []*http.Request, inner func(*http.Request, []*http.Request) error) error {
	if inner != nil {
		if err := inner(req, via); err != nil {
			return err
		}
	}
	if err := safeCheckRedirect(req, via); err != nil {
		return err
	}
	if len(via) == 0 {
		return nil
	}
	chain, err := newRedirectChain(via[0].URL.String(), defaultRedirectLimits())
	if err != nil {
		return fmt.Errorf("%w: 无法记录入口 URL", errSecureDownloadBadRedirect)
	}
	for _, hop := range via[1:] {
		if ok, reason := chain.Decide(hop.URL.String(), nil); !ok {
			recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
				"secure-download", "重定向中间跳被拒绝: "+reason+" -> "+hop.URL.String())
			return fmt.Errorf("%w: %s", errSecureDownloadBadRedirect, reason)
		}
	}
	if ok, reason := chain.Decide(req.URL.String(), nil); !ok {
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"secure-download", "重定向目标被拒绝: "+reason+" -> "+req.URL.String())
		return fmt.Errorf("%w: %s", errSecureDownloadBadRedirect, reason)
	}
	return nil
}

func streamVerifiedDownload(ctx context.Context, url, destPath string, opts secureDownloadOptions) (*secureDownloadResult, error) {
	if !isHTTPSURL(url) {
		return nil, fmt.Errorf("拒绝不安全的下载 URL（非 HTTPS）: %s", url)
	}
	// 短链 / 重定向预检：任何下载出发前先过 shortlinkguard。非短链 URL 只做
	// 协议与 userinfo 校验；短链 URL 追加目标主机私网判定（解析器走真实 DNS，
	// 域名命中私网 / 回环 / 链路本地即拒绝）。失败视为不可重试的硬错误。
	preflighted, err := preflightDownloadURL(url, nil)
	if err != nil {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"secure-download", "下载 URL 预检拒绝: "+err.Error())
		return nil, err
	}
	url = preflighted
	if opts.MaxBytes <= 0 {
		return nil, errSecureDownloadNoLimit
	}
	attempts := opts.Attempts
	if attempts <= 0 {
		attempts = secureDownloadDefaultAttempts
	}
	client := opts.Client
	if client == nil {
		client = safeHTTPClient()
	}
	client = wrapClientRedirectGuard(client)
	dir := filepath.Dir(destPath)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	// 目标路径已被符号链接 / 特殊文件占据时拒绝：rename 会跟随替换普通文件，
	// 但先挡住异常路径，避免被诱导把文件写到重解析点上。
	if bad, err := isSymlinkOrSpecial(destPath); err != nil {
		return nil, fmt.Errorf("检查目标路径失败: %w", err)
	} else if bad {
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"secure-download", "目标路径是符号链接或特殊文件，拒绝下载写入: "+destPath)
		return nil, fmt.Errorf("拒绝写入符号链接或非普通文件: %s", destPath)
	}

	var res *secureDownloadResult
	// fatal 表示重试没有意义（超限 / 哈希不符 / 4xx），由内核直接返回。
	used, err := runWithRetry(ctx, attempts, secureDownloadBackoffBase, func() (bool, error) {
		r, fatal, e := attemptSecureDownload(ctx, client, url, destPath, opts)
		res = r
		return fatal, e
	})
	if err != nil {
		return nil, err
	}
	res.Attempts = used
	return res, nil
}

// attemptSecureDownload 是单次尝试。返回 fatal=true 表示错误不可重试。
func attemptSecureDownload(ctx context.Context, client *http.Client, url, destPath string,
	opts secureDownloadOptions) (res *secureDownloadResult, fatal bool, err error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, true, fmt.Errorf("创建请求失败 %s: %w", url, err)
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		// 网络层错误（DNS / 连接重置 / 超时）视为瞬时错误，交给上层退避重试。
		return nil, false, fmt.Errorf("下载请求失败 %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		retryable := resp.StatusCode == http.StatusRequestTimeout ||
			resp.StatusCode == http.StatusTooManyRequests ||
			resp.StatusCode >= 500
		recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
			"secure-download",
			fmt.Sprintf("下载源返回 HTTP %d: %s", resp.StatusCode, url))
		if !retryable {
			return nil, true, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, url)
		}
		return nil, false, fmt.Errorf("%w: HTTP %d (%s)", errSecureDownloadStatus, resp.StatusCode, url)
	}

	// 声明体积超限：连响应体都不必读，直接拒绝（不可重试，服务端不会改口）。
	if resp.ContentLength > opts.MaxBytes {
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"secure-download",
			fmt.Sprintf("下载声明体积 %d 超过上限 %d: %s", resp.ContentLength, opts.MaxBytes, url))
		return nil, true, fmt.Errorf("%w: 声明体积 %d 超过上限 %d",
			errSecureDownloadTooLarge, resp.ContentLength, opts.MaxBytes)
	}

	// 服务器建议的文件名只作参考：解析失败或被安全校验拒绝时一律丢弃，避免
	// 上游把 Content-Disposition 里的路径 / 设备名 / 双向控制符直接带进落盘名。
	serverName := ""
	if cdHeader := resp.Header.Get("Content-Disposition"); cdHeader != "" {
		serverName = serverFilenameFromHeader(cdHeader)
		if serverName == "" {
			recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityWarn, auditActionRejected,
				"secure-download", "已丢弃不安全的 Content-Disposition 文件名: "+url)
		}
	}

	// 临时文件必须与目标同目录，rename 才是同卷原子操作。
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".dl-*")
	if err != nil {
		return nil, false, fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if err := tmp.Chmod(privateFilePerm); err != nil {
		cleanup()
		return nil, false, fmt.Errorf("设置临时文件权限失败: %w", err)
	}

	hasher := sha256.New()
	// 多读 1 字节：正好读到上限之后还有数据，说明实际超限。
	reader := io.LimitReader(resp.Body, opts.MaxBytes+1)
	buf := make([]byte, secureDownloadBufSize)
	var written int64

loop:
	for {
		select {
		case <-ctx.Done():
			cleanup()
			return nil, false, ctx.Err()
		default:
		}
		n, rerr := reader.Read(buf)
		if n > 0 {
			if _, werr := tmp.Write(buf[:n]); werr != nil {
				cleanup()
				return nil, false, fmt.Errorf("写入临时文件失败: %w", werr)
			}
			hasher.Write(buf[:n])
			written += int64(n)
			if opts.Progress != nil {
				opts.Progress(written, resp.ContentLength)
			}
		}
		switch {
		case rerr == io.EOF:
			break loop
		case rerr != nil:
			cleanup()
			// 连接中断通常是瞬时错误，允许重试。
			return nil, false, fmt.Errorf("读取下载数据失败: %w", rerr)
		}
	}

	if written > opts.MaxBytes {
		cleanup()
		recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
			"secure-download",
			fmt.Sprintf("下载实际体积 %d 超过上限 %d: %s", written, opts.MaxBytes, url))
		return nil, true, fmt.Errorf("%w: 实际体积 %d 超过上限 %d",
			errSecureDownloadTooLarge, written, opts.MaxBytes)
	}

	// 声明长度与实际不一致（仅在传输层未透明解压时才可比，gzip 自动解压时
	// Go 会清掉 Content-Length）。短斤少两的文件交给重试，重试用尽再失败。
	if resp.ContentLength > 0 && !resp.Uncompressed && written != resp.ContentLength {
		cleanup()
		return nil, false, fmt.Errorf("%w: 声明 %d 实际 %d (%s)",
			errSecureDownloadBadSize, resp.ContentLength, written, url)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expected := strings.ToLower(strings.TrimSpace(opts.ExpectedSHA256)); expected != "" {
		if !constantTimeEqualLowerHex(actualSHA, expected) {
			cleanup()
			recordSecurityEvent(auditCategoryHashVerify, auditSeverityCritical, auditActionBlocked,
				"secure-download",
				"下载文件 sha256 与期望值不符（期望值不记入日志）: "+url)
			return nil, true, fmt.Errorf("%w: %s", errSecureDownloadBadHash, url)
		}
	}

	if err := tmp.Sync(); err != nil {
		cleanup()
		return nil, false, fmt.Errorf("刷新临时文件到磁盘失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, false, fmt.Errorf("关闭临时文件失败: %w", err)
	}
	// 原子替换：此刻起目标路径要么是旧的完整文件，要么是新的完整文件，
	// 不存在半截状态。
	if err := os.Rename(tmpName, destPath); err != nil {
		os.Remove(tmpName)
		return nil, false, fmt.Errorf("原子替换目标文件失败: %w", err)
	}

	// 落盘成功后补 Windows 网络来源标记（MOTW）。MOTW 是纵深防御层，
	// 写失败只审计、不回滚文件本身——内容已通过全部校验。
	if opts.MarkWebOrigin {
		markDownloadWithWebOrigin(destPath, url, opts.ReferrerURL)
	}

	return &secureDownloadResult{Bytes: written, SHA256: actualSHA, ServerName: serverName}, false, nil
}

// constantTimeEqualLowerHex 在两个等长小写十六进制串之间做常量时间比较，
// 长度不同时仍提前返回（长度不是秘密），避免 sha256 校验引入时序侧信道。
func constantTimeEqualLowerHex(actual, expected string) bool {
	if len(actual) != len(expected) {
		return false
	}
	var v byte
	for i := 0; i < len(actual); i++ {
		v |= actual[i] ^ expected[i]
	}
	return v == 0
}

// wrapClientRedirectGuard 复制客户端并替换成受控重定向策略。不就地修改调用方
// 传入的 client，避免把一次性下载的收紧策略带给其它请求。
func wrapClientRedirectGuard(client *http.Client) *http.Client {
	if client == nil {
		client = safeHTTPClient()
	}
	inner := client.CheckRedirect
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return secureDownloadCheckRedirect(req, via, inner)
	}
	return &c
}

// serverFilenameFromHeader 从 Content-Disposition 解析服务器建议的文件名，并
// 要求它同时通过结构解析与落盘字符校验。任何一步不通过都返回空串，由调用方
// 继续使用自己生成的名字——绝不让服务端决定一个未校验的落盘路径。
func serverFilenameFromHeader(header string) string {
	if strings.TrimSpace(header) == "" {
		return ""
	}
	cd, err := ParseContentDisposition(header)
	if err != nil || cd == nil {
		return ""
	}
	name := cd.FilenameStar
	if name == "" {
		name = cd.Filename
	}
	if name == "" {
		return ""
	}
	if err := ValidateDownloadFilename(name); err != nil {
		return ""
	}
	return name
}

// streamVerifiedDownload 执行一次可校验、可重试、原子落盘的安全下载。
//
// 失败时目标路径不会留下残文件：数据始终写在同目录临时文件里，只有全部
// 校验通过并 fsync 后才 rename 到目标路径。
