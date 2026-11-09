package main

import (
	"strings"
)

// secureZipRelPath 校验 zip 条目名（去掉业务前缀后的相对路径）是否安全。
//
// zip 规范规定条目名一律用 '/' 分隔；这里故意不做任何平台相关的 Clean，
// 而是逐段手工过一遍，保证 Windows / Linux 行为一致：
//   - 空名、NUL 字节、反斜杠、前导 '/'、Windows 盘符 / UNC 一律拒绝；
//   - 出现 ".." 段（任何位置）一律拒绝，"."、空段会被折叠；
//   - 折叠后为空（例如 "./" 本身）也拒绝。
func secureZipRelPath(name string) (string, bool) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", false
	}
	if strings.ContainsRune(name, '\\') {
		return "", false
	}
	if strings.HasPrefix(name, "/") {
		return "", false
	}
	// Windows 盘符（C:x / C:/x）与传统 DOS 设备名前缀。
	if len(name) >= 2 && name[1] == ':' {
		return "", false
	}

	var segs []string
	for _, seg := range strings.Split(name, "/") {
		switch seg {
		case "", ".":
			continue
		case "..":
			return "", false
		default:
			segs = append(segs, seg)
		}
	}
	if len(segs) == 0 {
		return "", false
	}
	for _, seg := range segs {
		if zipSegmentUnsafeReason(seg) != "" {
			return "", false
		}
	}
	return strings.Join(segs, "/"), true
}

// secureDestUnder 复核目标绝对路径必须位于 root 之内（或等于 root）。
// rel 已在 secureZipRelPath 里验过，这里是落盘前的第二道保险，
// 防止平台路径语义差异或上层拼接失误造成逃逸。归属判定统一走
// pathguard.go 的 PathWithinRoot（Clean + 卷名归一 + 边界前缀比较），
// 不再在这里各写一份 Abs/HasPrefix。
