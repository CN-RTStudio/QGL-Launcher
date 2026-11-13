package main

import (
	"path/filepath"
	"strings"
)

func hasControlCharStr(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1F || s[i] == 0x7F {
			return true
		}
	}
	return false
}

func isValidUMFSHex(s string) bool {
	// UMFS hexdigest 只产出小写十六进制；不能用 hex.DecodeString（它会放行大写
	// A-F），否则同一内容可写入大小写两种哈希串，绕过账本的规范化去重。
	return IsLowerHex(s, 64)
}

// sanitizeModAuditEntry 逐字段净化账本条目；任何字段非法即整体丢弃（返回 false）。
func sanitizeModAuditEntry(raw *ModAuditEntry) bool {
	if raw == nil {
		return false
	}
	if !modAuditSafeRelPath(raw.RelPath) {
		return false
	}
	name := filepath.Base(strings.ReplaceAll(raw.RelPath, "/", string(filepath.Separator)))
	if name == "" || hasControlCharStr(name) || len(name) > 256 {
		return false
	}
	if raw.Size < 0 {
		return false
	}
	if !isValidUMFSHex(raw.UMFS) {
		return false
	}
	if raw.ModTime != "" && len(raw.ModTime) > 64 {
		return false
	}
	raw.Name = name
	return true
}
