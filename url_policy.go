package main

import (
	"fmt"
)

// 外部链接白名单：启动器里凡是从远程元数据（mod 页、更新日志、皮肤站）
// 拿到 URL 后要交给系统浏览器打开的，必须先过这里。
// 防止被恶意 mod 元数据塞 javascript: / file: / 内网地址等。
var allowedExternalHosts = map[string]bool{
	"www.minecraft.net":             true,
	"minecraft.net":                 true,
	"account.mojang.com":            true,
	"authserver.mojang.com":         true,
	"api.mojang.com":                true,
	"libraries.minecraft.net":       true,
	"piston-data.mojang.com":        true,
	"piston-meta.mojang.com":        true,
	"cdn.modrinth.com":              true,
	"api.modrinth.com":              true,
	"modrinth.com":                  true,
	"www.curseforge.com":            true,
	"curseforge.com":                true,
	"github.com":                    true,
	"raw.githubusercontent.com":     true,
	"objects.githubusercontent.com": true,
	"maven.fabricmc.net":            true,
	"bmclapi2.bangbang93.com":       true,
}

// rejectExternalURL 统一记录一次"外部链接被拒"安全事件并返回错误。
// raw 会过脱敏（token / 邮箱 / 内网 IP）与限长，避免把敏感 query 写进审计日志。
func rejectExternalURL(reason, raw string) error {
	recordSecurityEvent(auditCategoryExternalURL, auditSeverityWarn, auditActionRejected,
		"url_policy", reason+"："+raw)
	return fmt.Errorf("%s", reason)
}
