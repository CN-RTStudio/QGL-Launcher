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
