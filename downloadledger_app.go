package main

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
