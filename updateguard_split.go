package main

import "strings"

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
