package main

import (
	"path/filepath"
	"strings"
)

func validateAssetObjectName(name string) (string, string) {
	if name == "" {
		return "", aoRejectEmpty
	}
	if len(name) > maxAssetObjectNameLen {
		return "", aoRejectLen
	}
	// 拒绝 Windows 盘符 / UNC 与反斜杠：资源名永远是正斜杠相对路径。
	if strings.Contains(name, "\\") {
		return "", aoRejectBack
	}
	if strings.HasPrefix(name, "/") {
		return "", aoRejectAbs
	}
	// 拒绝任何 ".." 段（正斜杠 / 反斜杠 / 混合都算）。
	// 注意：不能只依赖 filepath.Clean——Windows 上 Clean 会把 "a/../b" 折叠成 "b"，
	// 使穿越探测被静默吞掉；这里必须在规范化前看原始输入。
	if containsDotDotSegment(name) {
		return "", aoRejectTrail
	}
	if hasWindowsDrivePrefix(name) {
		return "", aoRejectDrive
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return "", aoRejectCtrl
		}
	}
	// 用 ToSlash + Clean 规范化后必须仍是多段相对路径且不包含 ".." 段。
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.FromSlash(name))), "./")
	if clean == "" || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", aoRejectTrail
	}
	for _, seg := range strings.Split(clean, "/") {
		if !isAssetNameSegmentOK(seg) {
			return "", aoRejectSeg
		}
	}
	return clean, aoOK
}

// hasWindowsDrivePrefix 判断字符串是否以 X: 形式的盘符开头（如 C:foo）。
func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 {
		return false
	}
	c := p[0]
	driveLetter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	return driveLetter && p[1] == ':'
}
