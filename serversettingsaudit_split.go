package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func auditOnlineSettings(props *serverProperties, audit *ServerSettingsAudit) {
	if value, ok := props.Get("online-mode"); ok {
		if enabled, valid := settingBool(value); valid && !enabled {
			audit.Findings = append(audit.Findings, SettingFinding{
				Key: "online-mode", Value: value, Severity: settingsSeverityWarn,
				Message: "离线模式关闭了 Mojang 身份校验，任何人都能冒充任意玩家名",
			})
		}
	}
	if value, ok := props.Get("enforce-secure-profile"); ok {
		if enabled, valid := settingBool(value); valid && !enabled {
			audit.Findings = append(audit.Findings, SettingFinding{
				Key: "enforce-secure-profile", Value: value, Severity: settingsSeverityWarn,
				Message: "关闭安全聊天签名后，聊天消息可被第三方伪造",
			})
		}
	}
	if value, ok := props.Get("allow-flight"); ok {
		if enabled, valid := settingBool(value); valid && enabled {
			audit.Findings = append(audit.Findings, SettingFinding{
				Key: "allow-flight", Value: value, Severity: settingsSeverityInfo,
				Message: "允许飞行会放宽移动校验，作弊客户端更难被识别",
			})
		}
	}
	if value, ok := props.Get("max-players"); ok {
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < 1 || n > settingsMaxPlayersLimit {
			audit.Findings = append(audit.Findings, SettingFinding{
				Key: "max-players", Value: value, Severity: settingsSeverityWarn,
				Message: fmt.Sprintf("玩家上限不在 1-%d 区间", settingsMaxPlayersLimit),
			})
		}
	}
}
func auditResourcePackSetting(props *serverProperties, audit *ServerSettingsAudit) {
	value, ok := props.Get("resource-pack")
	if !ok || strings.TrimSpace(value) == "" {
		return
	}
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		audit.Findings = append(audit.Findings, SettingFinding{
			Key: "resource-pack", Value: value, Severity: settingsSeverityWarn,
			Message: "资源包不是 https 直链，客户端会在明文通道拉取可被替换的资源",
		})
		return
	}
	if sha1, ok := props.Get("resource-pack-sha1"); !ok || !IsLowerHex(strings.TrimSpace(sha1), 40) {
		audit.Findings = append(audit.Findings, SettingFinding{
			Key: "resource-pack-sha1", Value: "", Severity: settingsSeverityWarn,
			Message: "资源包缺少合法的 40 位小写十六进制 SHA1 摘要",
		})
	}
}
