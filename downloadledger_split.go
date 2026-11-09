package main

import (
	"net/url"
	"path/filepath"
	"strings"
)

// ledgerFileNameOnly 取落盘文件名（Windows/Unix 分隔符都剥掉，防路径穿越）。
func ledgerFileNameOnly(s string) string {
	base := filepath.Base(s)
	base = strings.ReplaceAll(base, "\\", "")
	base = strings.ReplaceAll(base, "/", "")
	return sanitizeLedgerField(base, maxLedgerNameBytes)
}

// ledgerAppend 向台账追加一条（去重：同 URL 同哈希的最新记录覆盖旧的，
// 防止同一文件重复下载把台账撑满）。返回新台账（不修改入参）。
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

// downloadLedgerStats 是台账的聚合统计（前端摘要展示）。
type downloadLedgerStats struct {
	Total     int `json:"total"`
	OK        int `json:"ok"`
	Mismatch  int `json:"mismatch"`
	Failed    int `json:"failed"`
	Oversized int `json:"oversized"`
	Skipped   int `json:"skipped"`
	Hosts     int `json:"hosts"`
}

// ledgerSummary 计算台账统计与去重主机数。
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
