package main

import (
	"net/url"
	"path/filepath"
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
