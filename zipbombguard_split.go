package main

func zbRatioExceeds(compressed, uncompressed int64, maxRatio int) bool {
	if compressed <= 0 {
		// 0 字节却有非 0 解压大小，视为无限放大（但允许真空文件）
		return uncompressed > 0
	}
	if uncompressed <= 0 {
		return false
	}
	// uncompressed/compressed > maxRatio  <=> uncompressed > compressed*maxRatio，避免浮点
	var cm int64 = int64(maxRatio)
	if compressed > (1<<63-1)/cm {
		return false // 乘积溢出时压缩量本身已极大，放大有限
	}
	return uncompressed > compressed*cm
}

// ZBHasReason 判定结果含某类问题。
func ZBHasReason(findings []ZBFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}
