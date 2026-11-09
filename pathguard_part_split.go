package main

import (
	"path/filepath"
	"strings"
)

// SafeSimpleName 校验不含任何分隔符的单段名字（资源索引 ID、版本号等），
// 防止把 "a/b" 或 "../x" 当作一个文件名片段拼接。
func SafeSimpleName(name string) string {
	if name == "" || len(name) > 256 {
		return ""
	}
	if strings.ContainsAny(name, `/\`) {
		return ""
	}
	if !validateSafeSegment(name) {
		return ""
	}
	return name
}

// SafeMojmapsMappingsPath 由不受信任的版本 JSON 中 data.MOJMAPS.client 值
// （形如 "group:artifact:version@txt"）推导官方 mappings 的落盘绝对路径。
// group 各段、artifact、version 全部走 SafeSimpleName 严格白名单，扩展名只允许
// 短小的小写字母数字，并最终用 PathWithinRoot 约束结果必须仍在 <mcDir>/libraries
// 之下，防止恶意安装器借 ".." 段、分隔符或带穿越的扩展名把文件写到 libraries 之外。
// 任一环节不合法都返回 ok=false（调用方按“跳过 mappings”处理，不影响启动）。
func SafeMojmapsMappingsPath(mcDir, coord, ext string) (string, bool) {
	parts := strings.Split(coord, ":")
	if len(parts) != 3 {
		return "", false
	}
	groupSegs := strings.Split(parts[0], ".")
	if len(groupSegs) == 0 {
		return "", false
	}
	relElems := make([]string, 0, len(groupSegs)+4)
	relElems = append(relElems, "libraries")
	for _, g := range groupSegs {
		gs := SafeSimpleName(g)
		if gs == "" {
			return "", false
		}
		relElems = append(relElems, gs)
	}
	artifact := SafeSimpleName(parts[1])
	version := SafeSimpleName(parts[2])
	if artifact == "" || version == "" {
		return "", false
	}
	if !safeMappingsExt(ext) {
		return "", false
	}
	relElems = append(relElems, artifact, version, artifact+"-"+version+"-mappings."+ext)
	target := filepath.Join(mcDir, filepath.Join(relElems...))
	if !PathWithinRoot(target, filepath.Join(mcDir, "libraries")) {
		return "", false
	}
	return target, true
}

// SafeMappingsVersionPath 由安装器 install_profile.json 里的 data.MOJMAPS.version
// 推导旧版 Forge mappings 的落盘路径。version 来自不可信 JSON，先过 SafeSimpleName
// 严格白名单（拒绝分隔符、冒号、".."、保留设备名），最终再用 PathWithinRoot 约束
// 结果必须仍在 <mcDir>/libraries 之下。
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
