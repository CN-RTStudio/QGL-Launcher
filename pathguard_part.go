package main

import (
	"strings"
)

// safeRelChar 是外部清单里“相对路径单段”允许出现的字符白名单。
// 只放行 Maven 坐标 / 资源索引 ID 真实会用到的字符，其余（分隔符、盘符冒号、
// 通配符、管道、引号、控制字符等）一律拒绝，从源头掐断盘符、ADS 与参数注入。
func safeRelChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	}
	switch r {
	case '.', '_', '-', '+', '~':
		return true
	}
	return false
}

// validateSafeSegment 校验单个路径段：非空、非 "."/".."、不含 Windows
// 保留设备名（CON/PRN/AUX/NUL/COMx/LPTx）、结尾不留空格或点。
func validateSafeSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	for _, r := range seg {
		if !safeRelChar(r) {
			return false
		}
	}
	// Windows 资源管理器 / Win32 会吞掉结尾的点和空格，可能造成同名绕过。
	if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
		return false
	}
	upper := strings.ToUpper(seg)
	if dot := strings.IndexByte(upper, '.'); dot >= 0 {
		upper = upper[:dot]
	}
	switch upper {
	case "CON", "PRN", "AUX", "NUL":
		return false
	}
	if len(upper) == 4 {
		p := upper[:3]
		if (p == "COM" || p == "LPT") && upper[3] >= '1' && upper[3] <= '9' {
			return false
		}
	}
	return true
}

// SafeMavenRelPath 校验外部清单给出的“正斜杠相对路径”（Maven library path、
// assetIndex id 等），返回归一化后的安全相对路径；不合法返回空串。
// 与 isSafeRelPath 的差别：后者只做 Clean/.. 排除，这里走严格字符白名单，
// 并拒绝反斜杠、冒号、盘符、绝对路径与保留设备名。
func SafeMavenRelPath(name string) string {
	if name == "" || len(name) > 1024 {
		return ""
	}
	for _, r := range name {
		if r == 0 || r < 0x20 {
			return ""
		}
	}
	if strings.ContainsRune(name, '\\') || strings.ContainsRune(name, ':') ||
		strings.HasPrefix(name, "/") {
		return ""
	}
	var segs []string
	for _, seg := range strings.Split(name, "/") {
		if !validateSafeSegment(seg) {
			return ""
		}
		segs = append(segs, seg)
	}
	if len(segs) == 0 {
		return ""
	}
	return strings.Join(segs, "/")
}
