package main

// respackjsonguard.go —— 资源包 JSON 清单路径校验。
//
// 资源包里 pack.mcmeta、sounds.json、lang/*.json 都会引用包内文件路径。
// 一个恶意资源包可以在 sounds.json 里写 `"sound.foo": {"sounds":["../../.minecraft/foo"]}`
// 让客户端去读包外文件，或塞控制字符污染日志。这里把“资源包内相对路径”的
// 合法性收敛成纯函数。

import (
	"fmt"
	"strings"
)

// ValidatePackAssetPath 校验资源包内引用路径是否安全。
// 规则：相对路径、不越出包根、无控制字符、无绝对路径、无 Windows 盘符。
func ValidatePackAssetPath(p string) error {
	s := strings.TrimSpace(p)
	if s == "" {
		return fmt.Errorf("empty asset path")
	}
	if strings.ContainsAny(s, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\r\n\t") {
		return fmt.Errorf("control chars in asset path: %q", s)
	}
	// 统一斜杠后做分段检查。
	norm := strings.ReplaceAll(s, "\\", "/")
	if strings.HasPrefix(norm, "/") {
		return fmt.Errorf("absolute path not allowed: %q", s)
	}
	if len(s) >= 2 && s[1] == ':' {
		return fmt.Errorf("windows drive path not allowed: %q", s)
	}
	parts := strings.Split(norm, "/")
	for _, seg := range parts {
		if seg == ".." {
			return fmt.Errorf("path traversal in asset: %q", s)
		}
		if seg == "" {
			return fmt.Errorf("empty segment in asset: %q", s)
		}
	}
	return nil
}

// IsSafePackAsset 便捷布尔入口。
func IsSafePackAsset(p string) bool {
	return ValidatePackAssetPath(p) == nil
}

// FilterPackAssetList 批量过滤，返回安全子集。
func FilterPackAssetList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if IsSafePackAsset(p) {
			out = append(out, p)
		}
	}
	return out
}
