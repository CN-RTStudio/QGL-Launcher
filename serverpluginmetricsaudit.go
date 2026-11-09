package main

import (
	"fmt"
	"os"
	"strings"
)

const (
	spmMaxFindings      = 48
	spmReasonOK         = "ok"
	spmReasonMissing    = "missing"
	spmReasonEnabled    = "telemetry-enabled"
	spmReasonCleartext  = "telemetry-cleartext-endpoint"
	spmReasonCreds      = "telemetry-endpoint-credentials"
	spmReasonIdentifier = "telemetry-stable-identifier"
	spmReasonBadValue   = "bad-value"
	spmReasonScanNote   = "scan"
	spmReasonDSN        = "telemetry-dsn"
	spmReasonIP         = "telemetry-ip-collection"
)

type PluginMetricsFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type PluginMetricsAudit struct {
	ServerDir   string
	ConfigCount int
	Findings    []PluginMetricsFinding
}

func (a *PluginMetricsAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= spmMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PluginMetricsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PluginMetricsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginMetricsFinding) bool { return f.Blocking })
}

func (a *PluginMetricsAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != spmReasonOK && f.Reason != spmReasonScanNote && !f.Blocking {
			return true
		}
	}
	return false
}

func (a *PluginMetricsAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginMetricsFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func spmToggleKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics", "bstats", "telemetry", "usage-stats", "usage_stats",
		"analytics", "tracking", "anonymous-statistics", "statistics", "sentry",
	})
}

func spmEndpointKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics-url", "metrics_url", "telemetry-url", "telemetry_url",
		"analytics-url", "analytics_url", "bstats-url", "bstats_url",
		"statistics-url", "sentry-dsn", "dsn",
	})
}

func spmIdentifierKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"metrics-uuid", "metrics_uuid", "server-uuid", "server_uuid",
		"installation-id", "install-id", "instance-id",
	})
}

func spmIPKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"collect-player-ips", "send-player-ips", "log-player-ips",
		"store-ips", "include-ip", "include_ips", "send-ip",
	})
}

func spmCheckEndpoints(a *PluginMetricsAudit, cfg spxConfig) {
	for _, key := range spmEndpointKeys(cfg.Flat) {
		value := strings.TrimSpace(cfg.Flat[key])
		if value == "" {
			a.add(cfg.Rel, spmReasonBadValue, "遥测端点为空: "+key, false)
			continue
		}
		if strings.HasSuffix(key, "dsn") && strings.HasPrefix(strings.ToLower(value), "https://") {
			a.add(cfg.Rel, spmReasonDSN, "配置了外部错误上报 DSN: "+key, false)
			continue
		}
		kind, risky := spxURLRisk(value)
		switch kind {
		case "cleartext":
			a.add(cfg.Rel, spmReasonCleartext, "遥测端点使用明文 HTTP: "+key, true)
		case "credentials":
			a.add(cfg.Rel, spmReasonCreds, "遥测端点内嵌凭据: "+key, false)
		case "local-or-legacy":
			a.add(cfg.Rel, spmReasonCleartext, "遥测端点使用本地或旧式协议: "+key, true)
		case "path-shape":
			a.add(cfg.Rel, spmReasonCreds, "遥测端点包含路径穿越片段: "+key, true)
		case "https":
			if strings.Contains(strings.ToLower(value), "sentry") {
				a.add(cfg.Rel, spmReasonDSN, "配置了外部错误上报 DSN: "+key, false)
			}
		}

		if risky {
			continue
		}
	}
}

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
