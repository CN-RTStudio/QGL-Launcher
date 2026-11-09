package main

import (
	"fmt"
	"os"
	"strings"
)

func spmCheckToggles(a *PluginMetricsAudit, cfg spxConfig) {
	enabled := false
	for _, key := range spmToggleKeys(cfg.Flat) {
		value := cfg.Flat[key]
		on, known := spxBool(value)
		switch {
		case !known:
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower == "https://bstats.org" || strings.HasPrefix(lower, "https://") {
				a.add(cfg.Rel, spmReasonEnabled, "遥测地址已配置: "+key, false)
				enabled = true
				continue
			}
			if key != "sentry" && key != "analytics" && key != "tracking" && key != "statistics" {
				continue
			}
			a.add(cfg.Rel, spmReasonBadValue, "遥测开关取值非法: "+key+"="+value, false)
		case on:
			enabled = true
			a.add(cfg.Rel, spmReasonEnabled, "插件启用了外部遥测: "+key, false)
		}
	}
	for _, key := range spmIdentifierKeys(cfg.Flat) {
		value := strings.TrimSpace(cfg.Flat[key])
		if value == "" {
			continue
		}
		a.add(cfg.Rel, spmReasonIdentifier, "遥测携带稳定安装标识: "+key, false)
	}
	for _, key := range spmIPKeys(cfg.Flat) {
		on, known := spxBool(cfg.Flat[key])
		if known && on {
			a.add(cfg.Rel, spmReasonIP, "插件配置收集玩家 IP: "+key, false)
		}
	}
	if enabled {
		a.add(cfg.Rel, spmReasonEnabled, "该插件会把运行数据发送到外部服务", false)
	}
}

func AuditServerPluginMetrics(serverDir string) *PluginMetricsAudit {
	a := &PluginMetricsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(".", spmReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", spmReasonScanNote, "服务器目录为符号链接", true)
		return a
	}
	if _, err := os.Stat(serverDir); err != nil {
		a.add(".", spmReasonMissing, "服务器目录不存在", false)
		return a
	}

	scan := spxScanPluginConfigs(serverDir)
	for _, note := range scan.Notes {
		a.add(note.File, note.Reason, note.Detail, note.Blocking)
	}
	a.ConfigCount = len(scan.Configs)
	if len(scan.Configs) == 0 {
		a.add("plugins", spmReasonMissing, "未找到可审计的插件配置文件", false)
		return a
	}
	for _, cfg := range scan.Configs {
		spmCheckEndpoints(a, cfg)
		spmCheckToggles(a, cfg)
	}
	a.add("plugins", spmReasonOK, fmt.Sprintf("共扫描 %d 个插件配置", a.ConfigCount), false)
	return a
}
