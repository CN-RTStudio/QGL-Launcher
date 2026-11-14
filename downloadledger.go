package main

import (
	"path/filepath"
	"sync"
)

const maxDownloadLedgerEntries = 200
const maxDownloadLedgerBytes int64 = 256 << 10 // 256 KiB
const (
	maxLedgerURLBytes  = 1024
	maxLedgerHashBytes = 128
	maxLedgerNameBytes = 200
)
const (
	LedgerStatusOK        = "ok"        // 下载完成且校验通过（或无需校验）
	LedgerStatusMismatch  = "mismatch"  // 哈希校验不通过（潜在供应链异常）
	LedgerStatusFailed    = "failed"    // 传输失败 / 中断
	LedgerStatusOversized = "oversized" // 体积超限被拒
	LedgerStatusSkipped   = "skipped"   // 缓存命中，未实际下载
)

type downloadLedgerEntry struct {
	URL        string `json:"url"`                  // 来源 URL（脱敏后）
	Host       string `json:"host"`                 // 来源主机（便于按域聚合审计）
	FileName   string `json:"fileName"`             // 落盘文件名（仅 basename，不含路径）
	TotalBytes int64  `json:"totalBytes"`           // 声明/实际字节数（-1 表示未知）
	Status     string `json:"status"`               // 见 LedgerStatus*
	HashAlgo   string `json:"hashAlgo"`             // sha1 / sha256 / sha512 / umfs / none
	Hash       string `json:"hash"`                 // 校验值（校验失败时为空）
	StartedAt  string `json:"startedAt"`            // RFC3339
	FinishedAt string `json:"finishedAt,omitempty"` // RFC3339
}

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
