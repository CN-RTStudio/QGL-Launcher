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
