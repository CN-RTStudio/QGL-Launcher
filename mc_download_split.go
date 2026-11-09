package main

import (
	"errors"
	"fmt"
	"path/filepath"
)

func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	return a.downloadFileBounded(url, destPath, reportProgress, maxUnverifiedDownloadBytes)
}
func (a *App) downloadFileBounded(url string, destPath string, reportProgress bool, maxBytes int64) error {
	if !isHTTPSURL(url) {
		return fmt.Errorf("拒绝不安全的下载 URL（非 HTTPS）: %s", url)
	}
	dir := filepath.Dir(destPath)
	// 统一走 ensurePrivateDir：除创建外还会把已存在但权限过宽（如历史 0755）的目录
	// 收敛到 0700。所有 downloadFile/downloadFileBounded/downloadVerifiedFile 都汇聚到这里，
	// 各调用点不再各自 MkdirAll。
	if err := ensurePrivateDir(dir); err != nil {
		return fmt.Errorf("创建目录失败 %s: %w", dir, err)
	}
	state := inspectRegularFile(destPath)
	if state.Exists && !state.trustable() {
		reason := describeUntrustedFile(state, destPath)
		recordSecurityEvent(auditCategoryPrivateWrite, auditSeverityCritical, auditActionBlocked,
			"download-cache", reason)
		return fmt.Errorf("%s", reason)
	}
	if state.trustable() && state.Size > 0 {
		return nil
	}
	ctx, cancelReq := a.downloadContext()
	defer cancelReq()
	opts := secureDownloadOptions{
		MaxBytes:  maxBytes,
		Attempts:  3,
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		Client:    safeHTTPClient(),
	}
	if reportProgress {
		opts.Progress = func(received, total int64) {
			a.emitProgress("downloading", filepath.Base(destPath), received, total)
		}
	}
	if _, err := streamVerifiedDownload(ctx, url, destPath, opts); err != nil {
		// 下载台账：传输失败留痕（无论是否有哈希期望，失败都要可审计）。
		a.RecordDownloadEntry(url, ledgerHostOf(url), filepath.Base(destPath), "", "", LedgerStatusFailed, -1)
		if errors.Is(err, errSecureDownloadTooLarge) {
			return fmt.Errorf("下载失败 %s: %w", url, errDownloadTooLarge)
		}
		return fmt.Errorf("下载失败 %s: %v", url, err)
	}
	return nil
}
