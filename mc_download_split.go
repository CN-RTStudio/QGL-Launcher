package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (a *App) downloadFile(url string, destPath string, reportProgress bool) error {
	return a.downloadFileBounded(url, destPath, reportProgress, maxUnverifiedDownloadBytes)
}

// downloadFileBounded 与 downloadFile 相同，但允许调用方按文件类型指定体积上限，
// 让版本 JSON / 资产索引等小元数据不必套用 4 GiB 的宽松上限。
//
// 实际的 HTTP 请求 / 体积双校验 / 流式 sha256 / 原子落盘 / 503 退避重试统一走
// streamVerifiedDownload：这里只保留"已存在跳过""进度上报到前端""错误归一化"
// 三层 App 语义，避免各下载点各自手写请求体。
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

// downloadVerifiedFile 下载并校验官方 SHA1；缓存命中走侧车摘要链
// （UMFS -> SHA512 -> SHA1）快速复用，新下载落盘则以官方 SHA1 为唯一信任锚
// 校验通过后再补写 UMFS/SHA512 侧车；校验失败删除重下一次。
func (a *App) downloadVerifiedFile(url string, destPath string, expectedSHA1 string, reportProgress bool) error {
	if expectedSHA1 == "" {
		return a.downloadFile(url, destPath, reportProgress)
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA1))
	if state := inspectRegularFile(destPath); state.trustable() && state.Size > 0 && a.verifyCachedFile(destPath, expected) {
		return nil
	}
	os.Remove(destPath)
	removeCachedFileMeta(destPath)
	if err := a.downloadFile(url, destPath, reportProgress); err != nil {
		return err
	}
	// 外部协议摘要（Mojang SHA1）保持原算法，是首次下载唯一的权威校验。
	if !a.checkFileHash(destPath, expected) {
		os.Remove(destPath)
		removeCachedFileMeta(destPath)
		// 下载台账：官方 SHA1 校验不通过 = 潜在供应链异常，critical 留痕。
		a.RecordDownloadEntry(url, ledgerHostOf(url), filepath.Base(destPath), "sha1", expected, LedgerStatusMismatch, -1)
		return fmt.Errorf("SHA1 校验失败: %s", destPath)
	}
	// 官方 SHA1 已通过：本地缓存摘要用 bool-hybrid-array 生态的 UMFS 优先记录。
	if err := a.saveCachedFileMeta(destPath, expected); err != nil {
		a.writeLog("缓存元数据写入失败（不影响完整性）: %s: %v", destPath, err)
	}
	// 下载台账：Mojang SHA1 校验通过后记 ok（哈希保持原算法 sha1）。
	a.RecordDownloadEntry(url, ledgerHostOf(url), filepath.Base(destPath), "sha1", expected, LedgerStatusOK, -1)
	return nil
}
