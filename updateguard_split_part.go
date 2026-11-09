package main

import "strings"

func isIPLiteralHost(host string) bool {
	if strings.Contains(host, ":") {
		return true
	}
	_, ok := parseDestIP(host)
	return ok
}

// hostAllowed 判断 host 是否等于白名单项或为其子域（label 边界匹配）。
func hostAllowed(host string, allow []string) bool {
	for _, a := range allow {
		a = strings.ToLower(a)
		if host == a {
			return true
		}
		if strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// sanitizeUpdateAssetName 校验发布资产文件名：不得为空、超长、含路径分隔与
// 控制字符。assetName 只允许是一个"文件名"，任何路径形状（含 / \ ..）都拒绝。
func sanitizeUpdateAssetName(name string, limits UpdateLimits) (string, bool) {
	l := limits.withDefaults()
	if name == "" || len(name) > l.AssetNameLen {
		return "", false
	}
	if strings.ContainsAny(name, "/\\") || strings.Contains(name, "..") {
		return "", false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return name, true
}
