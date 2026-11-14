package main

import (
	"strconv"
	"strings"
)

func (a *App) getSecureJarHandlerVersion(versionID string, versionJSON *VersionJSON) string {
	for _, lib := range versionJSON.Libraries {
		if strings.Contains(lib.Name, "securejarhandler") {
			// lib.Name 格式: "cpw.mods:securejarhandler:0.9.45"
			parts := strings.Split(lib.Name, ":")
			if len(parts) >= 3 {
				return parts[2]
			}
		}
	}
	return ""
}

// parseMCVersion 解析 MC 版本号，返回 (major, minor, patch)
func parseMCVersion(versionID string) (int, int, int) {
	// 去除可能的快照后缀
	versionID = strings.Split(versionID, "-")[0]
	versionID = strings.Split(versionID, " ")[0]

	parts := strings.Split(versionID, ".")
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	patch := 0
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return major, minor, patch
}

// SelectJavaForVersion 为指定 MC 版本选择合适的 Java
