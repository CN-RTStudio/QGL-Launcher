package main

import (
	"fmt"
	"time"
)

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
