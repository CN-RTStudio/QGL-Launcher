package main

// downloadledger_app.go —— 下载台账的 App 绑定层。
//
// 与 sessionjournal 同构：包级单例 store + 首次访问从磁盘有界加载 +
// 每次变更原子私有写。写盘失败只记审计事件，不阻塞下载主流程。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// downloadLedgerStore 是下载台账的内存权威。
type downloadLedgerStore struct {
	sync.Mutex
	loaded bool
	items  []downloadLedgerEntry
}

// defaultDownloadLedger 是全局下载台账单例。
var defaultDownloadLedger downloadLedgerStore

// downloadLedgerPath 返回台账文件路径（QGL 目录下）。
func (a *App) downloadLedgerPath() string {
	return filepath.Join(a.GetQGLDir(), "download-ledger.json")
}

// loadDownloadLedger 从磁盘有界加载台账；脏文件按空台账处理。
func loadDownloadLedger(path string) []downloadLedgerEntry {
	var entries []downloadLedgerEntry
	if err := readLocalJSONBounded(path, &entries, maxDownloadLedgerBytes, "download-ledger"); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			recordSecurityEvent("download-ledger", auditSeverityWarn, auditActionStripped,
				"download-ledger", fmt.Sprintf("下载台账读取失败，按空台账处理: %v", err))
		}
		return nil
	}
	cleaned := make([]downloadLedgerEntry, 0, len(entries))
	for _, e := range entries {
		cleaned = append(cleaned, sanitizeLedgerEntry(e, time.Now()))
	}
	return cleaned
}

// saveDownloadLedger 原子私有写台账；失败只记审计事件，不上抛。
func (a *App) saveDownloadLedgerLocked() {
	if err := writePrivateJSONBounded(a.downloadLedgerPath(), defaultDownloadLedger.items, maxDownloadLedgerBytes); err != nil {
		recordSecurityEvent("download-ledger", auditSeverityWarn, auditActionFailed,
			"download-ledger", fmt.Sprintf("下载台账写盘失败: %v", err))
	}
}

// ensureDownloadLedgerLoaded 确保内存台账已从磁盘加载。
func (a *App) ensureDownloadLedgerLoaded() {
	defaultDownloadLedger.Lock()
	defer defaultDownloadLedger.Unlock()
	if !defaultDownloadLedger.loaded {
		defaultDownloadLedger.items = loadDownloadLedger(a.downloadLedgerPath())
		defaultDownloadLedger.loaded = true
	}
}

// RecordDownloadEntry 记录一次下载行为（脱敏后入账并持久化）。
// 供下载完成/失败/校验失败的收尾点调用；哈希校验用外部 API 原算法（Mojang
// SHA1、authlib SHA256、Modrinth sha1/sha512），此处只记账不改变校验算法。
func (a *App) RecordDownloadEntry(url, host, fileName, hashAlgo, hash, status string, totalBytes int64) {
	a.ensureDownloadLedgerLoaded()
	now := time.Now()
	entry := sanitizeLedgerEntry(downloadLedgerEntry{
		URL: url, Host: host, FileName: fileName, TotalBytes: totalBytes,
		Status: status, HashAlgo: hashAlgo, Hash: hash,
		StartedAt: now.Format(time.RFC3339), FinishedAt: now.Format(time.RFC3339),
	}, now)
	if entry.Status == LedgerStatusMismatch {
		recordSecurityEvent("download-ledger", auditSeverityCritical, auditActionBlocked,
			"download-ledger", fmt.Sprintf("下载校验不通过已入账: %s (%s)", entry.FileName, entry.URL))
	}
	defaultDownloadLedger.Lock()
	defer defaultDownloadLedger.Unlock()
	defaultDownloadLedger.items = ledgerAppend(defaultDownloadLedger.items, entry)
	a.saveDownloadLedgerLocked()
}

// ListDownloadLedger 返回台账快照（新→旧）与统计。limit<=0 时取全部。
func (a *App) ListDownloadLedger(limit int) ([]downloadLedgerEntry, downloadLedgerStats) {
	a.ensureDownloadLedgerLoaded()
	defaultDownloadLedger.Lock()
	defer defaultDownloadLedger.Unlock()
	items := defaultDownloadLedger.items
	if limit <= 0 || limit > len(items) {
		limit = len(items)
	}
	if limit < len(items) {
		items = items[len(items)-limit:]
	}
	stats := ledgerSummary(defaultDownloadLedger.items)
	return items, stats
}

// ClearDownloadLedger 清空台账（审计事件留痕后写盘），返回清空条数。
func (a *App) ClearDownloadLedger() int {
	a.ensureDownloadLedgerLoaded()
	defaultDownloadLedger.Lock()
	defer defaultDownloadLedger.Unlock()
	n := len(defaultDownloadLedger.items)
	if n > 0 {
		recordSecurityEvent("download-ledger", auditSeverityInfo, auditActionReset,
			"download-ledger", fmt.Sprintf("清空下载台账 %d 条", n))
		defaultDownloadLedger.items = nil
		a.saveDownloadLedgerLocked()
	}
	return n
}
