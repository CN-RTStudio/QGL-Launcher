package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	settingsSeverityInfo     = "info"
	settingsSeverityWarn     = "warn"
	settingsSeverityCritical = "critical"
	settingsRconMinPassword  = 8
	settingsMaxPlayersLimit  = 2000
)

type SettingFinding struct {
	Key      string
	Value    string
	Severity string
	Message  string
}

type ServerSettingsAudit struct {
	Findings []SettingFinding
}

func (audit ServerSettingsAudit) Blocking() bool {
	for _, finding := range audit.Findings {
		if finding.Severity == settingsSeverityCritical {
			return true
		}
	}
	return false
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

func AuditServerSettings(props *serverProperties) ServerSettingsAudit {
	audit := ServerSettingsAudit{}
	if props == nil {
		return audit
	}
	auditRconSettings(props, &audit)
	auditOnlineSettings(props, &audit)
	auditResourcePackSetting(props, &audit)
	return audit
}

func AuditServerSettingsFile(serverDir string) (ServerSettingsAudit, error) {
	path := filepath.Join(serverDir, "server.properties")
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ServerSettingsAudit{}, nil
		}
		return ServerSettingsAudit{}, fmt.Errorf("检查 server.properties 失败: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ServerSettingsAudit{}, fmt.Errorf("server.properties 不是普通文件，拒绝读取")
	}
	if info.Size() > worldProbeBytes {
		return ServerSettingsAudit{}, fmt.Errorf("server.properties 超过 %d 字节上限", worldProbeBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return ServerSettingsAudit{}, fmt.Errorf("打开 server.properties 失败: %v", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, worldProbeBytes+1))
	if err != nil {
		return ServerSettingsAudit{}, fmt.Errorf("读取 server.properties 失败: %v", err)
	}
	if len(raw) > worldProbeBytes {
		return ServerSettingsAudit{}, fmt.Errorf("server.properties 超过 %d 字节上限", worldProbeBytes)
	}
	return AuditServerSettings(parseServerProperties(raw)), nil
}
