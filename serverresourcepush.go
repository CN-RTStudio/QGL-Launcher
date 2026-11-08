package main

// serverresourcepush.go —— 服务器强制资源包（server-resource-pack）推送校验。
//
// MC 服务器在加入时可以下发资源包 URL，要求客户端下载并加载；恶意服务器可以
// 把 URL 指到内网/非 CDN 主机做 SSRF，或指到 http:// 明文链接窃听。这里把
// “这个包 URL 该不该让启动器替玩家下载”收敛成纯函数。

import (
	"fmt"
	"net/url"
	"strings"
)

// 服务器资源包 URL 允许的主机后缀（Mojang CDN + 用户显式允许的自定义主机）。
var allowedPackHostSuffixes = []string{
	".minecraft.net",
	".mojang.com",
	".minecraftservices.com",
}

// ValidateServerPackURL 校验服务器下发的资源包 URL。
// extraAllowed 是用户在服务器配置里显式放行的主机（不含协议）。
func ValidateServerPackURL(raw string, extraAllowed []string) error {
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("empty server pack url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("bad pack url: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("server pack must be https, got %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("empty host in pack url")
	}
	for _, suf := range allowedPackHostSuffixes {
		if host == strings.TrimPrefix(suf, ".") || strings.HasSuffix(host, suf) {
			return nil
		}
	}
	for _, a := range extraAllowed {
		if strings.EqualFold(host, strings.TrimSpace(a)) {
			return nil
		}
	}
	return fmt.Errorf("server pack host not allowed: %s", host)
}

// IsAllowedServerPack 便捷布尔入口。
func IsAllowedServerPack(raw string, extra []string) bool {
	return ValidateServerPackURL(raw, extra) == nil
}

// FilterServerPackList 批量过滤。
func FilterServerPackList(in []string, extra []string) []string {
	out := make([]string, 0, len(in))
	for _, p := range in {
		if IsAllowedServerPack(p, extra) {
			out = append(out, p)
		}
	}
	return out
}
