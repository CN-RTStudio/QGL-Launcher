package main

import (
	"fmt"
	"net/url"
	"strings"
)

// safeExternalURL 校验 url 是否允许交给系统浏览器打开。
// 只允许 https、标准 443 端口、host 必须在白名单内，
// 且不允许 userinfo（防 https://github.com@evil.com 这类视觉混淆）。
func safeExternalURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return rejectExternalURL("空 URL", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return rejectExternalURL("URL 解析失败: "+err.Error(), raw)
	}
	if u.Scheme != "https" {
		return rejectExternalURL(fmt.Sprintf("只允许 https:// 链接，收到 %q", u.Scheme), raw)
	}
	if u.User != nil {
		return rejectExternalURL(fmt.Sprintf("外部链接不允许携带用户信息(userinfo): %s", u.Host), raw)
	}
	// 只放行默认 https 端口；显式写 :8080 之类一律拒绝，避免借端口绕过白名单心智。
	if port := u.Port(); port != "" && port != "443" {
		return rejectExternalURL(fmt.Sprintf("外部链接只允许 443 端口，收到 %q", port), raw)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return rejectExternalURL("外部链接缺少主机名", raw)
	}
	if !allowedExternalHosts[host] {
		return rejectExternalURL(fmt.Sprintf("host %q 不在外部链接白名单内", host), raw)
	}
	return nil
}
