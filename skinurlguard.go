package main

// skinurlguard.go —— 玩家皮肤/披风纹理下载 URL 的出站策略内核（纯函数）。
//
// 启动器在换肤、离线皮肤、同步披风时会拿一个纹理 URL 去下载。这个 URL 来源
// 多样（玩家自定义、第三方站、甚至复制粘贴），直接交给 safeHTTPClient 之前，
// 要先收敛成：必须 https、host 在允许名单内或为官方纹理域、拒绝 IP 字面量与
// 用户信息（user:pass@host）。否则它就是一个让启动器替攻击者向内网发请求的
// SSRF 入口。本模块只做判定，不下载、不联网。

import (
	"net/url"
	"strings"
)

// skinAllowHosts 是允许直接下载纹理的官方/可信纹理域。
var skinAllowHosts = []string{
	"textures.minecraft.net",
	"mc-heads.net",
	"crafatar.com",
	"minotar.net",
}

// skinDecision 是一次判定结果。
type skinDecision struct {
	Allow bool
	Why   string
	Host  string
}

// classifySkinURL 判定一个纹理 URL 是否允许发起下载。
func classifySkinURL(raw string) skinDecision {
	if strings.TrimSpace(raw) == "" {
		return skinDecision{Allow: false, Why: "empty url"}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return skinDecision{Allow: false, Why: "parse error"}
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" {
		return skinDecision{Allow: false, Why: "scheme must be https", Host: u.Hostname()}
	}
	if u.User != nil {
		return skinDecision{Allow: false, Why: "userinfo not allowed in texture url", Host: u.Hostname()}
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return skinDecision{Allow: false, Why: "empty host"}
	}
	// IP 字面量不允许（避免 169.254/127/内网）。
	if isIPLiteralHost(host) {
		return skinDecision{Allow: false, Why: "ip literal host rejected", Host: host}
	}
	for _, ok := range skinAllowHosts {
		if host == ok || strings.HasSuffix(host, "."+ok) {
			return skinDecision{Allow: true, Why: "allowlisted host", Host: host}
		}
	}
	// 其余域名一律不自动放行，交给上层让用户显式确认；不在这里偷偷放行。
	return skinDecision{Allow: false, Why: "host not in allowlist", Host: host}
}

// allowSkinDownload 便捷布尔入口。
func allowSkinDownload(raw string) bool {
	return classifySkinURL(raw).Allow
}
