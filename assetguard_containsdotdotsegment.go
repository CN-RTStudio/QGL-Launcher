package main

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
func validateAssetObjectHash(hash string) bool {
	return IsLowerHex(hash, 40)
}

func validateAssetObjectSize(size int64) bool {
	return size >= 0 && size <= maxAssetObjectSizeDecl
}

// planAssetObjectDest 把一个已通过哈希校验的对象映射到 objects 目录下的
// "<objectsDir>/<hh>/<40hex>" 目标，并用 PathWithin 复核结果没有越出 objects 目录。
// 返回子目录名、完整目标路径与是否安全。
