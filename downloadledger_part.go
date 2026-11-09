package main

import (
	"strings"
	"time"
)

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
