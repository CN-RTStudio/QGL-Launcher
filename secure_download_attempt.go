package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

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
