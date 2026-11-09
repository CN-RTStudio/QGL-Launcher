package main

import (
	"fmt"
	"strconv"
	"strings"
)

func settingOrDefault(props *serverProperties, key, fallback string) string {
	if value, ok := props.Get(key); ok {
		return value
	}
	return fallback
}

func settingBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

func auditRconSettings(props *serverProperties, audit *ServerSettingsAudit) {
	enabled, _ := settingBool(settingOrDefault(props, "enable-rcon", "false"))
	if enabled {
		password, _ := props.Get("rcon.password")
		if strings.TrimSpace(password) == "" {
			audit.Findings = append(audit.Findings, SettingFinding{
				Key: "enable-rcon", Value: "true", Severity: settingsSeverityCritical,
				Message: "启用了 RCON 却没有设置 rcon.password，远程控制台等于对全网开放",
			})
		} else if len(password) < settingsRconMinPassword {
			audit.Findings = append(audit.Findings, SettingFinding{
				Key: "rcon.password", Value: "***", Severity: settingsSeverityWarn,
				Message: fmt.Sprintf("RCON 密码短于 %d 字符，容易被暴力枚举", settingsRconMinPassword),
			})
		}
		if port, ok := props.Get("rcon.port"); ok {
			n, err := strconv.Atoi(strings.TrimSpace(port))
			if err != nil || n < 1024 || n > 65535 {
				audit.Findings = append(audit.Findings, SettingFinding{
					Key: "rcon.port", Value: port, Severity: settingsSeverityWarn,
					Message: "RCON 端口不在 1024-65535 区间",
				})
			}
		}
	}
}
