package main

import (
	"path/filepath"
	"testing"
)

func spuReasons(a *PluginUpdateAudit) map[string]bool {
	out := map[string]bool{}
	for _, f := range a.Findings {
		out[f.Reason] = true
	}
	return out
}

func TestAuditServerPluginUpdatesMissingDir(t *testing.T) {
	a := AuditServerPluginUpdates(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonMissing] {
		t.Fatalf("expected missing: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesNoPlugins(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerPluginUpdates(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if a.ConfigCount != 0 {
		t.Fatalf("expected zero configs, got %d", a.ConfigCount)
	}
}

func TestAuditServerPluginUpdatesCleanPlugin(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/ExamplePlugin/config.yml", "settings:\n  auto-update: false\n  update-url: https://example.com/update.json\n")
	a := AuditServerPluginUpdates(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if a.ConfigCount != 1 {
		t.Fatalf("expected one config, got %d", a.ConfigCount)
	}
	if spuReasons(a)[spuReasonAuto] {
		t.Fatalf("unexpected auto-update finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesAutoUpdate(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Updater/config.yml", "update-check: true\n")
	a := AuditServerPluginUpdates(dir)
	if !spuReasons(a)[spuReasonAuto] {
		t.Fatalf("expected auto-update finding: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonNoSource] {
		t.Fatalf("expected no-source finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesCleartextSource(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Bad/config.yml", "auto-update: true\nupdate-url: http://updates.example.com/latest.jar\n")
	a := AuditServerPluginUpdates(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonInsecure] {
		t.Fatalf("expected insecure finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesLocalSource(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Bad/config.yml", "download-url: file:///srv/plugins/latest.jar\n")
	a := AuditServerPluginUpdates(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonInsecure] {
		t.Fatalf("expected insecure finding: %s", a.Describe())
	}
}
