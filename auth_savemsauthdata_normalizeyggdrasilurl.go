package main

import (
	"strings"

)

func normalizeYggdrasilURL(serverURL string) string {
	serverURL = strings.TrimSpace(serverURL)
	serverURL = strings.TrimSuffix(serverURL, "/")
	// 如果不以 /api/yggdrasil 结尾，自动添加
	if !strings.HasSuffix(serverURL, "/api/yggdrasil") {
		serverURL = serverURL + "/api/yggdrasil"
	}
	return serverURL
}

// GetYggdrasilServerInfo 获取 Yggdrasil 服务器信息
