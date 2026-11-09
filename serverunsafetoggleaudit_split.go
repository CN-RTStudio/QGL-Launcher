package main

import (
	"os"
	"strings"
)

func AuditServerUnsafeToggles(serverDir string) *UnsafeToggleAudit {
	a := &UnsafeToggleAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", sunReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sunReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", sunReasonMissing, "服务器目录不存在", false)
		return a
	}

	if text, ok := sunLoadText(a, serverDir, "server.properties", sunMaxProps); ok {
		props := pxParseProperties(text)
		if value, found := props["enforce-secure-profile"]; found {
			if strings.EqualFold(strings.TrimSpace(value), "false") {
				a.add("server.properties", sunReasonSecureOff, "enforce-secure-profile=false 允许未签名聊天", false)
			}
		}
		if value, found := props["network-compression-threshold"]; found {
			if number, parsed := cfgParseInt(strings.TrimSpace(value)); !parsed {
				a.add("server.properties", sunReasonBadValue, "network-compression-threshold 非整数", true)
			} else if number > 0 && number < 64 {
				a.add("server.properties", sunReasonBadValue, "network-compression-threshold 过小", false)
			}
		}
	}

	text, ok := sunLoadText(a, serverDir, "config/paper-global.yml", sunMaxYAML)
	if !ok {
		return a
	}
	flat := cfgFlattenYAML(text)

	if value, found := sunBool(flat, "unsupported-settings.perform-username-validation"); found && !value {
		a.add("config/paper-global.yml", sunReasonUsername, "关闭用户名校验，可伪造玩家名", true)
	}
	if value, found := sunBool(flat, "unsupported-settings.allow-perm-gen"); found && value {
		a.add("config/paper-global.yml", sunReasonPermGen, "允许权限生成器写入配置", true)
	}

	reported := map[string]bool{
		"unsupported-settings.perform-username-validation": true,
		"unsupported-settings.allow-perm-gen":              true,
	}
	for key := range flat {
		if !strings.HasPrefix(key, "unsupported-settings.") {
			continue
		}
		if reported[key] {
			continue
		}
		enabled, parsed := sunBool(flat, key)
		if !parsed || !enabled {
			continue
		}
		a.add("config/paper-global.yml", sunReasonToggle, sunToggleDetail(key), true)
	}

	if raw, found := cfgLookup(flat, "watchdog.early-warning-every"); found {
		switch strings.ToLower(cfgStripQuotes(raw)) {
		case "true", "false":
			a.add("config/paper-global.yml", sunReasonBadValue, "watchdog.early-warning-every 为布尔值", true)
		}
	}
	return a
}
