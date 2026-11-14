package main

import (
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
