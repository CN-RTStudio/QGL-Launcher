package main

import (
	"net/url"
	"strings"
)

func (c *redirectChain) Decide(location string, resolveIP HostResolver) (allow bool, reason string) {
	if len(c.links) >= c.limits.MaxHops {
		return false, "too-many-hops"
	}
	loc := strings.TrimSpace(location)
	if loc == "" {
		return false, "empty-location"
	}
	prev, err := url.Parse(c.links[len(c.links)-1])
	if err != nil {
		return false, "bad-prev-url"
	}
	next, err := resolveLocation(prev, loc)
	if err != nil {
		return false, "bad-location-url"
	}

	scheme := strings.ToLower(next.Scheme)
	if scheme != "http" && scheme != "https" {
		return false, "non-http-scheme"
	}
	// 只有在链路里已经出现过 https 之后又落回 http，才算危险降级；入口本身就是
	// http（且 AllowDropToHTTP 关闭）时，http→http 同协议延续不应被误判为降级。
	if scheme == "http" && !c.limits.AllowDropToHTTP && c.schemes["https"] {
		return false, "downgrade-to-http"
	}
	if next.User != nil {
		return false, "userinfo-not-allowed"
	}
	host := strings.ToLower(next.Hostname())
	if host == "" {
		return false, "empty-host"
	}

	// 环检测：规范化后完全重复的 URL 直接拒绝。
	key := normalizeRedirectURL(next)
	if c.seen[key] {
		return false, "redirect-loop"
	}

	// 字面量 IP：用与出向拨号同一套宽解析器 parseDestIP 识别，连十进制整数 /
	// 十六进制 / 八进制 / IPv4-mapped 等混淆写法一并拦截，避免 2130706433 这类
	// 形态躲过私网判定形成 SSRF。
	ip, isIPLiteral := parseDestIP(host)
	if isIPLiteral && isPrivateOrLocalIP(ip) {
		return false, "host-not-public"
	}

	// 跨主机策略：默认允许跨主机（下载场景 CDN 切换常见），但收紧模式下
	// 只允许同注册域后缀；无论哪种模式，每跳主机都要过私网检查。
	if !c.limits.AllowCrossHost && !sameRegistrable(host, c.firstHost) {
		return false, "cross-host-denied"
	}

	if resolveIP != nil && !isIPLiteral {
		ips, err := resolveIP(host)
		if err != nil || len(ips) == 0 {
			return false, "dns-resolve-failed"
		}
		// DNS 重绑定优先判定：同主机名前后解析到的地址集不一致即拒绝，
		// 即便第二次恰好也是私网（127.0.0.1）也要报成 dns-rebinding。
		if prevIPs, ok := c.hostIPs[host]; ok && !ipSetEqual(prevIPs, ips) {
			return false, "dns-rebinding"
		}
		for _, ip := range ips {
			if isPrivateOrLocalIP(ip) {
				return false, "host-not-public"
			}
		}
		c.hostIPs[host] = ips
	}

	c.seen[key] = true
	c.schemes[scheme] = true
	c.links = append(c.links, next.String())
	return true, ""
}
