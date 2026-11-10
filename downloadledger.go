package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
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

func sanitizeLedgerEntry(e downloadLedgerEntry, now time.Time) downloadLedgerEntry {
	out := downloadLedgerEntry{
		URL:        sanitizeLedgerField(e.URL, maxLedgerURLBytes),
		Host:       sanitizeLedgerField(e.Host, 200),
		FileName:   ledgerFileNameOnly(e.FileName),
		TotalBytes: e.TotalBytes,
		Status:     e.Status,
		HashAlgo:   sanitizeLedgerField(strings.ToLower(e.HashAlgo), 16),
		Hash:       sanitizeLedgerField(strings.ToLower(e.Hash), maxLedgerHashBytes),
		StartedAt:  e.StartedAt,
		FinishedAt: e.FinishedAt,
	}
	if out.Status == "" {
		out.Status = LedgerStatusFailed
	}
	if out.TotalBytes < -1 {
		out.TotalBytes = -1
	}
	if out.StartedAt == "" {
		out.StartedAt = now.Format(time.RFC3339)
	}
	return out
}

func sanitizeLedgerField(s string, maxBytes int) string {
	runes := []rune(s)
	var sb strings.Builder
	sb.Grow(len(runes))
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0x1b && i+1 < len(runes) && runes[i+1] == '[' {
			// 跳过 CSI 序列直到终结字节（与会话日志同一口径，防残留 "[31m"）。
			i += 2
			for i < len(runes) {
				c := runes[i]
				if c >= 0x40 && c <= 0x7e {
					break
				}
				i++
			}
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		sb.WriteRune(r)
	}
	out := sb.String()
	if len(out) > maxBytes {
		out = out[:maxBytes]
	}
	return out
}

func ledgerFileNameOnly(s string) string {
	base := filepath.Base(s)
	base = strings.ReplaceAll(base, "\\", "")
	base = strings.ReplaceAll(base, "/", "")
	return sanitizeLedgerField(base, maxLedgerNameBytes)
}
func ledgerAppend(entries []downloadLedgerEntry, e downloadLedgerEntry) []downloadLedgerEntry {
	out := make([]downloadLedgerEntry, 0, len(entries)+1)
	added := false
	for _, old := range entries {
		if old.URL == e.URL && old.HashAlgo == e.HashAlgo && old.Hash == e.Hash {
			// 同源同哈希：用新记录替换（保留最新时间与状态），不加倍。
			if !added {
				out = append(out, e)
				added = true
			}
			continue
		}
		out = append(out, old)
	}
	if !added {
		out = append(out, e)
	}
	if len(out) > maxDownloadLedgerEntries {
		out = out[len(out)-maxDownloadLedgerEntries:]
	}
	return out
}

type downloadLedgerStats struct {
	Total     int `json:"total"`
	OK        int `json:"ok"`
	Mismatch  int `json:"mismatch"`
	Failed    int `json:"failed"`
	Oversized int `json:"oversized"`
	Skipped   int `json:"skipped"`
	Hosts     int `json:"hosts"`
}

func ledgerSummary(entries []downloadLedgerEntry) downloadLedgerStats {
	var s downloadLedgerStats
	hosts := make(map[string]struct{}, 8)
	for _, e := range entries {
		s.Total++
		hosts[e.Host] = struct{}{}
		switch e.Status {
		case LedgerStatusOK:
			s.OK++
		case LedgerStatusMismatch:
			s.Mismatch++
		case LedgerStatusFailed:
			s.Failed++
		case LedgerStatusOversized:
			s.Oversized++
		case LedgerStatusSkipped:
			s.Skipped++
		}
	}
	s.Hosts = len(hosts)
	return s
}

// ledgerHostOf 从下载 URL 提取主机（解析失败返回空串）。
func ledgerHostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return sanitizeLedgerField(u.Host, 200)
	}
	return ""
}

// ledgerTrimHash 只保留哈希前缀用于界面展示（避免整条哈希刷屏）。
func ledgerTrimHash(h string, keep int) string {
	if len(h) <= keep {
		return h
	}
	return h[:keep] + "…"
}
