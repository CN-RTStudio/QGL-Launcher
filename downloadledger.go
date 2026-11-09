package main

import (
	"strings"
	"time"
)

// maxDownloadLedgerEntries 台账环形保留的最大条目数。
const maxDownloadLedgerEntries = 200

// maxDownloadLedgerBytes 台账落盘文件的最大字节数。
const maxDownloadLedgerBytes int64 = 256 << 10 // 256 KiB

// maxLedgerURLBytes / maxLedgerHashBytes / maxLedgerNameBytes 单字段上限。
const (
	maxLedgerURLBytes  = 1024
	maxLedgerHashBytes = 128
	maxLedgerNameBytes = 200
)

// downloadLedgerStatus 是下载结局的分类（可扩展，保持字符串便于前端直显）。
const (
	LedgerStatusOK        = "ok"        // 下载完成且校验通过（或无需校验）
	LedgerStatusMismatch  = "mismatch"  // 哈希校验不通过（潜在供应链异常）
	LedgerStatusFailed    = "failed"    // 传输失败 / 中断
	LedgerStatusOversized = "oversized" // 体积超限被拒
	LedgerStatusSkipped   = "skipped"   // 缓存命中，未实际下载
)

// downloadLedgerEntry 是台账中的一行记录。
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

// sanitizeLedgerEntry 对入参做收口（URL 限长、文件名取 basename 并去控制符、
// 哈希小写限长、状态白名单兜底）。不修改入参，返回净化后的副本。
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

// sanitizeLedgerField 去控制字符（含 ESC[… 的 CSI 可视序列整段跳过）并限长。
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
