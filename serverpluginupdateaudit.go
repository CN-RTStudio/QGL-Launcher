package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	spuMaxFindings    = 48
	spuReasonOK       = "ok"
	spuReasonMissing  = "missing"
	spuReasonAuto     = "auto-update-enabled"
	spuReasonInsecure = "update-source-insecure"
	spuReasonCreds    = "update-source-credentials"
	spuReasonPath     = "update-source-path-shape"
	spuReasonNoSource = "update-without-source"
	spuReasonChannel  = "update-channel-unstable"
	spuReasonBadValue = "bad-value"
	spuReasonScanNote = "scan"
)

type PluginUpdateFinding = auditFinding

type PluginUpdateAudit struct {
	ServerDir   string
	ConfigCount int
	Findings    []PluginUpdateFinding
}

func (a *PluginUpdateAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spuMaxFindings, PluginUpdateFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PluginUpdateAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginUpdateFinding) bool { return f.Blocking })
}

func (a *PluginUpdateAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginUpdateFinding) bool {
		return f.Reason != spuReasonOK && f.Reason != spuReasonScanNote && !f.Blocking
	})
}

func (a *PluginUpdateAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginUpdateFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func spuAutoUpdateKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"auto-update", "auto_update", "update-check", "update_check",
		"check-for-updates", "check_for_updates", "update-on-start",
	})
}

func spuSourceKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"update-url", "update_url", "download-url", "download_url",
		"update-check-url", "update_check_url", "update-repository", "repository-url",
	})
}

func spuCheckConfig(a *PluginUpdateAudit, cfg spxConfig) {
	autoKeys := spuAutoUpdateKeys(cfg.Flat)
	sourceKeys := spuSourceKeys(cfg.Flat)

	autoEnabled := false
	for _, key := range autoKeys {
		enabled, known := spxBool(cfg.Flat[key])
		switch {
		case !known:
			a.add(cfg.Rel, spuReasonBadValue, "自动更新开关取值非法: "+key+"="+cfg.Flat[key], false)
		case enabled:
			autoEnabled = true
			a.add(cfg.Rel, spuReasonAuto, "插件启用自动更新，更新包未经过本地校验: "+key, false)
		}
	}

	sourceCount := 0
	for _, key := range sourceKeys {
		kind, risky := spxURLRisk(cfg.Flat[key])
		switch kind {
		case "empty":
			a.add(cfg.Rel, spuReasonBadValue, "更新源地址为空: "+key, false)
			continue
		case "credentials":
			a.add(cfg.Rel, spuReasonCreds, "更新源地址内嵌凭据: "+key, true)
		case "path-shape":
			a.add(cfg.Rel, spuReasonPath, "更新源地址包含路径穿越或反斜杠: "+key, true)
		case "cleartext":
			a.add(cfg.Rel, spuReasonInsecure, "更新源使用明文 HTTP: "+key, true)
		case "local-or-legacy":
			a.add(cfg.Rel, spuReasonInsecure, "更新源使用本地或旧式协议: "+key, true)
		case "https":
			sourceCount++
		}
		if risky {
			continue
		}
		if strings.Contains(strings.ToLower(cfg.Flat[key]), "github.com") {
			sourceCount++
		}
	}

	if autoEnabled && sourceCount == 0 {
		a.add(cfg.Rel, spuReasonNoSource, "自动更新已启用但没有声明可信更新源", false)
	}

	channelKeys := spxKeysWithSuffix(cfg.Flat, []string{"update-channel", "update_channel", "release-channel", "channel"})
	for _, key := range channelKeys {
		value := strings.ToLower(strings.TrimSpace(cfg.Flat[key]))
		switch value {
		case "", "stable", "release", "production":
		case "dev", "dev-build", "nightly", "snapshot", "beta", "alpha", "canary":
			a.add(cfg.Rel, spuReasonChannel, "更新通道为不稳定分支: "+key+"="+value, false)
		default:
			if strings.Contains(value, "dev") || strings.Contains(value, "beta") || strings.Contains(value, "snapshot") {
				a.add(cfg.Rel, spuReasonChannel, "更新通道含有不稳定标识: "+key+"="+value, false)
			}
		}
	}
}

func AuditServerPluginUpdates(serverDir string) *PluginUpdateAudit {
	a := &PluginUpdateAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spuReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spuReasonScanNote, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spuReasonMissing, "服务器目录不存在", false)
		return a
	}

	scan := spxScanPluginConfigs(serverDir)
	for _, note := range scan.Notes {
		a.add(note.File, note.Reason, note.Detail, note.Blocking)
	}
	a.ConfigCount = len(scan.Configs)
	if len(scan.Configs) == 0 {
		a.add("plugins", spuReasonMissing, "未找到可审计的插件配置文件", false)
		return a
	}
	for _, cfg := range scan.Configs {
		spuCheckConfig(a, cfg)
	}
	a.add("plugins", spuReasonOK, fmt.Sprintf("共扫描 %d 个插件配置", a.ConfigCount), false)
	return a
}
