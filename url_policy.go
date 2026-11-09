package main

import (
	"fmt"
	"net/url"
	"strings"
)

// 外部链接白名单：启动器里凡是从远程元数据（mod 页、更新日志、皮肤站）
// 拿到 URL 后要交给系统浏览器打开的，必须先过这里。
// 防止被恶意 mod 元数据塞 javascript: / file: / 内网地址等。
var allowedExternalHosts = map[string]bool{
	"www.minecraft.net":          true,
	"minecraft.net":              true,
	"account.mojang.com":         true,
	"authserver.mojang.com":      true,
	"api.mojang.com":             true,
	"libraries.minecraft.net":    true,
	"piston-data.mojang.com":     true,
	"piston-meta.mojang.com":     true,
	"cdn.modrinth.com":           true,
	"api.modrinth.com":           true,
	"modrinth.com":               true,
	"www.curseforge.com":         true,
	"curseforge.com":             true,
	"github.com":                 true,
	"raw.githubusercontent.com":  true,
	"objects.githubusercontent.com": true,
	"maven.fabricmc.net":         true,
	"bmclapi2.bangbang93.com":    true,
}

// rejectExternalURL 统一记录一次"外部链接被拒"安全事件并返回错误。
// raw 会过脱敏（token / 邮箱 / 内网 IP）与限长，避免把敏感 query 写进审计日志。
func rejectExternalURL(reason, raw string) error {
	recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
		"url_policy", reason+"："+raw)
	return fmt.Errorf("%s", reason)
}

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