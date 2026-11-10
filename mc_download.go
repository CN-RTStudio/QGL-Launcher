package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxUnverifiedDownloadBytes int64 = 4 << 30
const maxMetadataJSONBytes int64 = 16 << 20
const maxAssetObjectBytes int64 = 256 << 20

var errDownloadTooLarge = errors.New("下载体积超过安全上限")

type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, errDownloadTooLarge
	}
	return n, err
}

var errLocalFileTooLarge = errors.New("本地文件超过安全读取上限")

const localTextConfigMaxBytes int64 = 64 << 20

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

func readBoundedFile(path string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		return nil, errors.New("readBoundedFile 必须指定正的体积上限")
	}
	if bad, err := isSymlinkOrSpecial(path); err != nil {
		return nil, err
	} else if bad {
		return nil, fmt.Errorf("拒绝读取符号链接或非普通文件: %s", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if info, err := f.Stat(); err == nil && info.Size() > maxBytes {
		return nil, fmt.Errorf("%w: 文件 %s 体积 %d 超过上限 %d",
			errLocalFileTooLarge, path, info.Size(), maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: 文件 %s 实际超过上限 %d",
			errLocalFileTooLarge, path, maxBytes)
	}
	return data, nil
}

// downloadContext 返回一个与“下载列表取消信号”绑定的 context。
// 之前 CancelDownloadList 只能在两个文件之间跳出循环，正在传输的大文件
// 仍要等下完才停；把请求挂到这个 context 上后，取消会立刻中断进行中的 HTTP 读取。
// 非下载列表场景（如启动时补全文件）没有取消信号，返回普通 Background context。
func (a *App) downloadContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	a.downloadMutex.Lock()
	ch := a.downloadCancel
	a.downloadMutex.Unlock()
	if ch == nil {
		return ctx, cancel
	}
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}
