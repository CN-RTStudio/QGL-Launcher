package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
