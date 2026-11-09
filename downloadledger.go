package main

// downloadledger.go —— 启动器下载行为的可审计台账内核。
//
// 启动器会从 Mojang / authlib / Modrinth / 镜像等外部源拉取版本 JSON、库、
// Java 包与 mod。每次下载的来源、体积、哈希算法与校验结果都应留痕，供
// 事后排查「这个文件是哪来的、校验过没有」。纯函数层不依赖 App 与平台
// API，可独立单测；持久化复用小端有界私有写。

import (
	"net/url"
	"path/filepath"
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
