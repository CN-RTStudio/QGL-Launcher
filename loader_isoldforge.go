package main

import (
	_ "embed"
	"strconv"
	"strings"

)



func isOldForge(versionStr string) bool {
	// versionStr 类似 "1.16.5-34.1.0" 或 "34.1.0"
	parts := strings.Split(versionStr, "-")
	verPart := parts[len(parts)-1] // 取最后一段
	majorStr := strings.Split(verPart, ".")[0]
	major, err := strconv.Atoi(majorStr)
	if err != nil {
		return false
	}
	return major < 20
}

// InstallForge 安装 Forge（完全按照 PCL 逻辑）
