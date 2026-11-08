package main

import (
	"os"
	"path/filepath"
	"testing"
)

func spmWrite(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spmReasons(a *PluginMetricsAudit) map[string]bool {
	out := map[string]bool{}
	for _, f := range a.Findings {
		out[f.Reason] = true
	}
	return out
}

func TestAuditServerPluginMetricsMissingDir(t *testing.T) {
	a := AuditServerPluginMetrics(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !spmReasons(a)[spmReasonMissing] {
		t.Fatalf("expected missing: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsCleanConfig(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Clean/config.yml", "settings:\n  metrics: false\n")
	a := AuditServerPluginMetrics(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if spmReasons(a)[spmReasonEnabled] {
		t.Fatalf("unexpected telemetry finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsEnabledToggle(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "bstats: true\n")
	a := AuditServerPluginMetrics(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !spmReasons(a)[spmReasonEnabled] {
		t.Fatalf("expected telemetry finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsCleartextEndpoint(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "metrics-url: http://metrics.example.com/v1\n")
	a := AuditServerPluginMetrics(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spmReasons(a)[spmReasonCleartext] {
		t.Fatalf("expected cleartext finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsLocalEndpoint(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "telemetry-url: file:///var/lib/telemetry.sock\n")
	a := AuditServerPluginMetrics(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spmReasons(a)[spmReasonCleartext] {
		t.Fatalf("expected local endpoint finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsCredentialEndpoint(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "analytics-url: https://user:token@stats.example.com/v1\n")
	a := AuditServerPluginMetrics(dir)
	if !spmReasons(a)[spmReasonCreds] {
		t.Fatalf("expected credential finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsStableIdentifier(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "metrics: true\nmetrics-uuid: 11111111-2222-3333-4444-555555555555\n")
	a := AuditServerPluginMetrics(dir)
	if !spmReasons(a)[spmReasonIdentifier] {
		t.Fatalf("expected identifier finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsIPCollection(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "collect-player-ips: true\n")
	a := AuditServerPluginMetrics(dir)
	if !spmReasons(a)[spmReasonIP] {
		t.Fatalf("expected ip finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsSentryDSN(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "sentry-dsn: https://key@sentry.example.com/42\n")
	a := AuditServerPluginMetrics(dir)
	if !spmReasons(a)[spmReasonDSN] {
		t.Fatalf("expected dsn finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsEmptyEndpoint(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "metrics-url: \"\"\n")
	a := AuditServerPluginMetrics(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !spmReasons(a)[spmReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsPathEndpoint(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "bstats-url: https://stats.example.com/../internal\n")
	a := AuditServerPluginMetrics(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spmReasons(a)[spmReasonCreds] {
		t.Fatalf("expected path finding: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerPluginMetrics(link)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsMultipleConfigs(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/A/config.yml", "metrics: false\n")
	spmWrite(t, dir, "plugins/B/config.yml", "bstats: true\n")
	a := AuditServerPluginMetrics(dir)
	if a.ConfigCount != 2 {
		t.Fatalf("expected two configs, got %d", a.ConfigCount)
	}
	if !a.HasWarnings() {
		t.Fatalf("expected warnings: %s", a.Describe())
	}
}

func TestAuditServerPluginMetricsDescribeContent(t *testing.T) {
	dir := t.TempDir()
	spmWrite(t, dir, "plugins/Stats/config.yml", "telemetry: true\nmetrics-url: http://metrics.example.com/v1\n")
	a := AuditServerPluginMetrics(dir)
	if a.Describe() == "" {
		t.Fatalf("expected description")
	}
	if !a.Blocking() {
		t.Fatalf("expected blocking")
	}
}
