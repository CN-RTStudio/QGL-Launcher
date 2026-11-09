package main

import "path/filepath"

func SafeMappingsVersionPath(mcDir, version string) (string, bool) {
	v := SafeSimpleName(version)
	if v == "" {
		return "", false
	}
	target := filepath.Join(mcDir, "libraries", "net", "minecraft", "client", v,
		"client-"+v+"-mappings.txt")
	if !PathWithinRoot(target, filepath.Join(mcDir, "libraries")) {
		return "", false
	}
	return target, true
}

// safeMappingsExt 限制 mappings 扩展名只能是不超过 8 个字符的小写字母数字（官方为 txt）。
func safeMappingsExt(ext string) bool {
	if ext == "" || len(ext) > 8 {
		return false
	}
	for i := 0; i < len(ext); i++ {
		c := ext[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// IsLowerHex 报告 s 是否恰好是 n 个小写十六进制字符（用于校验外部 SHA1 等哈希）。
func IsLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
