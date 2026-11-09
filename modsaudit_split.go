package main

import (
	"path/filepath"
	"strings"
)

// modAuditSafeRelPath 判断账本里的相对路径是否可接受：非空、不超长、不含控制字符、
// 不是绝对路径、不含 ".." 段、不用反斜杠（账本统一正斜杠）。
func modAuditSafeRelPath(p string) bool {
	if p == "" || len(p) > modAuditRelPathMaxLen {
		return false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "\\") {
		return false
	}
	if strings.Contains(p, "\\") {
		return false
	}
	if hasControlCharStr(p) {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// hasControlCharStr 判断字符串是否含 ASCII 控制字符（与 nameguard 口径一致）。
func hasControlCharStr(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x1F || s[i] == 0x7F {
			return true
		}
	}
	return false
}

// isValidUMFSHex 判断账本里的哈希是否 64 位小写十六进制（UMFS 输出 32 字节）。
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

// ---- 目录扫描 ----

// listModAuditFiles 平铺列出 mods 目录下（含一层子目录）的普通文件相对路径，跳过
// 符号链接 / 设备 / 管道等特殊条目，并受条目数与子目录数上界约束。返回相对路径
// 列表（正斜杠）、跳过计数、是否触及上限。
