package main

import (
	"os"
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

func TestAuditServerPluginUpdatesCredentialSource(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Bad/config.yml", "update-url: https://user:pass@updates.example.com/latest.jar\n")
	a := AuditServerPluginUpdates(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonCreds] {
		t.Fatalf("expected credentials finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesPathShapeSource(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Bad/config.yml", "update-url: https://example.com/../../etc/passwd\n")
	a := AuditServerPluginUpdates(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonPath] {
		t.Fatalf("expected path finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesEmptySource(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Empty/config.yml", "update-url: \"\"\n")
	a := AuditServerPluginUpdates(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spuReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesUnstableChannel(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/Chan/config.yml", "auto-update: true\nupdate-url: https://example.com/update.json\nupdate-channel: nightly\n")
	a := AuditServerPluginUpdates(dir)
	if !spuReasons(a)[spuReasonChannel] {
		t.Fatalf("expected channel finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesSymlinkConfig(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "srv")
	if err := os.MkdirAll(filepath.Join(dir, "plugins", "Link"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(base, "outside.yml")
	if err := os.WriteFile(target, []byte("auto-update: true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "plugins", "Link", "config.yml")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerPluginUpdates(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spxReasonSymlink] {
		t.Fatalf("expected symlink finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesOversizedConfig(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, spxMaxConfigBytes+1024)
	for i := range big {
		big[i] = 'a'
	}
	path := filepath.Join(dir, "plugins", "Big", "config.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, big, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditServerPluginUpdates(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !spuReasons(a)[spxReasonTooLarge] {
		t.Fatalf("expected too-large finding: %s", a.Describe())
	}
}

func TestAuditServerPluginUpdatesMultiplePlugins(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "plugins/A/config.yml", "auto-update: true\n")
	auditWriteFileAtRoot(t, dir, "plugins/B/config.yaml", "update-url: https://example.com/update.json\n")
	auditWriteFileAtRoot(t, dir, "plugins/C/settings.yml", "update-check: false\n")
	a := AuditServerPluginUpdates(dir)
	if a.ConfigCount != 3 {
		t.Fatalf("expected three configs, got %d", a.ConfigCount)
	}
}
