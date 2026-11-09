package main

import (
	"path/filepath"
)

func containsDotDotSegment(p string) bool {
	if p == ".." {
		return true
	}
	runes := []rune(p)
	segStart := 0
	for i := 0; i <= len(runes); i++ {
		if i == len(runes) || runes[i] == '/' || runes[i] == '\\' {
			if i > segStart {
				seg := string(runes[segStart:i])
				if seg == ".." {
					return true
				}
			}
			segStart = i + 1
		}
	}
	return false
}

// validateAssetObjectHash 资源对象哈希必须是 40 位小写十六进制（SHA-1）。
// 这是 Mojang 外部信任锚，保持原 SHA-1 算法，不替换为本地 UMFS。
func validateAssetObjectHash(hash string) bool {
	return IsLowerHex(hash, 40)
}

// validateAssetObjectSize 校验索引声明的字节数：非负且不超过单对象上限。
func validateAssetObjectSize(size int64) bool {
	return size >= 0 && size <= maxAssetObjectSizeDecl
}

// planAssetObjectDest 把一个已通过哈希校验的对象映射到 objects 目录下的
// "<objectsDir>/<hh>/<40hex>" 目标，并用 PathWithin 复核结果没有越出 objects 目录。
// 返回子目录名、完整目标路径与是否安全。
func planAssetObjectDest(objectsDir, hash string) (string, string, bool) {
	if !validateAssetObjectHash(hash) {
		return "", "", false
	}
	sub := hash[:2]
	dest := filepath.Join(objectsDir, sub, hash)
	// hash 已严格限定为 40 位小写 hex，词法上无法逃逸，仍做一次归属判定作为纵深防御。
	if !PathWithinRoot(dest, objectsDir) {
		return "", "", false
	}
	return sub, dest, true
}

// SafeAssetObject 是通过校验、可安全下载 / 落盘的单个资源对象。
type SafeAssetObject struct {
	Name string // 规范化后的资源相对路径（仅用于拼下载 URL 与日志）
	Hash string // 40 位小写十六进制
	Size int64  // 声明字节数
}
