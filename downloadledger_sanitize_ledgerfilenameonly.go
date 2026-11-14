package main

import (
	"path/filepath"
	"strings"
)

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
