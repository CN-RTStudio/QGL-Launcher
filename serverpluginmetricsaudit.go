package main

import (
	"fmt"
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

type PluginMetricsFinding = auditFinding

type PluginMetricsAudit struct {
	ServerDir   string
	ConfigCount int
	Findings    []PluginMetricsFinding
}

func (a *PluginMetricsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spmMaxFindings, PluginMetricsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PluginMetricsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginMetricsFinding) bool { return f.Blocking })
}

func (a *PluginMetricsAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginMetricsFinding) bool {
		return f.Reason != spmReasonOK && f.Reason != spmReasonScanNote && !f.Blocking
	})
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
