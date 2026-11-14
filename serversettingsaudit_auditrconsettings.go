package main

import (
	"fmt"
	"strconv"
	"strings"
)

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

func (audit ServerSettingsAudit) HasWarnings() bool {
	return len(audit.Findings) > 0
}
func (audit ServerSettingsAudit) Codes() []string {
	var codes []string
	for _, finding := range audit.Findings {
		codes = append(codes, finding.Key+"="+finding.Value)
	}
	return codes
}
func (audit ServerSettingsAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "服务器配置未发现风险项"
	}
	var parts []string
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s=%s): %s", finding.Severity, finding.Key, finding.Value, finding.Message))
	}
	return strings.Join(parts, "；")
}
