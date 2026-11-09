package main

import (
	"strings"
)

// sanitizeUpdateUrl 校验更新包下载地址：
//   - 必须 https；
//   - 长度受限；
//   - 不允许嵌入用户信息（user:pass@）；
//   - host 必须命中白名单（精确或子域）；
//   - 不允许把 IP 文字形式当 host（IP 直连的更新源无法做域名级信任）。
//
// 返回 {ok, host, reason}。
func sanitizeUpdateUrl(raw string, limits UpdateLimits) (bool, string, string) {
	l := limits.withDefaults()
	if len(raw) > l.UrlLenMax {
		return false, "", "更新 URL 超过长度上限"
	}
	if !strings.HasPrefix(raw, "https://") {
		return false, "", "更新 URL 必须使用 HTTPS"
	}
	rest := raw[len("https://"):]
	if at := strings.Index(rest, "@"); at >= 0 {
		return false, "", "更新 URL 不允许携带用户信息"
	}
	slash := strings.IndexAny(rest, "/?#")
	var hostPort string
	if slash < 0 {
		hostPort = rest
	} else {
		hostPort = rest[:slash]
	}
	host := hostPort
	if idx := strings.LastIndex(hostPort, ":"); idx > 0 && strings.IndexByte(hostPort[idx+1:], ':') < 0 {
		host = hostPort[:idx]
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return false, "", "更新 URL 缺少主机名"
	}
	// IP 文字形式（IPv4 / IPv6）一律拒绝：更新源必须可审计的域名。
	if isIPLiteralHost(host) {
		return false, "", "更新 URL 不允许 IP 直连"
	}
	if !hostAllowed(host, allowedUpdateHosts) {
		return false, "", "更新源域名不在白名单内"
	}
	return true, host, ""
}

// isIPLiteralHost 报告 host 是否是 IP 字面量（IPv6 含冒号即算；IPv4 走宽解析器）。
// 收敛到 parseDestIP：旧实现只认严格四段十进制，单整数 2130706433、
// 十六进制 0x7f000001、八进制 0177.0.0.1、短格式 127.1 都会漏过"拒绝裸 IP"这道门，
// 被误当成域名。更新源 / Forge 镜像 / 服务器列表三处调用方一同受益。
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

// ParseVersionParts 把版本号拆成可比较的 token 序列（数字段按数值、非数字段
// 按 rune 序，数字 token 排在字母 token 之前）。"9.9" 与 "9.10" 由此正确比较。
// 返回 nil 表示版本号非法（空 / 超长 / 含控制字符）。
