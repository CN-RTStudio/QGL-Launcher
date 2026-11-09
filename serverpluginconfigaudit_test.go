package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writePC(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestAuditServerPluginConfigMissing(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerPluginConfig(dir)
	if len(audit.Findings) != 2 {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != pcReasonMissing || audit.Findings[0].Blocking {
		t.Fatalf("missing plugins dir should be informational: %+v", audit.Findings)
	}
}

func TestAuditServerPluginConfigClean(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "Example", "config.yml"), "enabled: true\nlanguage: zh_CN\n")
	audit := AuditServerPluginConfig(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != pcReasonOK {
		t.Fatalf("expected clean: %+v", audit.Findings)
	}
	if audit.Files[0] != filepath.Join("plugins", "Example", "config.yml") {
		t.Fatalf("unexpected file list: %v", audit.Files)
	}
}

func TestAuditServerPluginConfigDangerousToggle(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "Perm", "settings.yml"), "debug: true\nbypass-permissions: 'true'\nallow_unsafe: yes\n")
	audit := AuditServerPluginConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("dangerous toggles must block: %+v", audit.Findings)
	}
	if len(audit.Findings) != 3 {
		t.Fatalf("expected three findings: %+v", audit.Findings)
	}
	for _, f := range audit.Findings {
		if f.Reason != pcReasonDangerousToggle {
			t.Fatalf("unexpected reason: %+v", f)
		}
	}
}

func TestAuditServerPluginConfigDisabledToggle(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "Perm", "settings.yml"), "debug: false\nbypass_permissions: off\n")
	audit := AuditServerPluginConfig(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("disabled toggles should stay clean: %+v", audit.Findings)
	}
}

func TestAuditServerPluginConfigPlaintextSecret(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "Chat", "config.yml"), "password: hunter2\ntoken: abcd1234\napi-key: ''\n")
	audit := AuditServerPluginConfig(dir)
	if audit.Blocking() {
		t.Fatalf("plaintext secret is a warning: %+v", audit.Findings)
	}
	if !audit.HasWarnings() {
		t.Fatalf("expected warnings")
	}
	warns := 0
	for _, f := range audit.Findings {
		if f.Reason == pcReasonPlaintextSecret {
			warns++
		}
	}
	if warns != 2 {
		t.Fatalf("expected two secret warnings, got %d: %+v", warns, audit.Findings)
	}
}

func TestAuditServerPluginConfigEnvSecretAllowed(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "Chat", "config.yml"), "password: ${CHAT_PASSWORD}\n")
	audit := AuditServerPluginConfig(dir)
	if audit.HasWarnings() {
		t.Fatalf("env placeholder should not warn: %+v", audit.Findings)
	}
}

func TestAuditServerPluginConfigSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.yml")
	if err := os.WriteFile(target, []byte("enabled: true\n"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "plugins", "Evil", "config.yml")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerPluginConfig(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != pcReasonSymlink {
		t.Fatalf("expected symlink block: %+v", audit.Findings)
	}
}

func TestAuditServerPluginConfigTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := "padding: " + string(make([]byte, pcMaxFileBytes)) + "\n"
	if err := os.MkdirAll(filepath.Join(dir, "plugins", "Big"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugins", "Big", "config.yml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit := AuditServerPluginConfig(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != pcReasonTooLarge {
		t.Fatalf("expected too-large: %+v", audit.Findings)
	}
}

func TestAuditServerPluginConfigTopLevelFile(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "legacy.conf"), "enabled: true\n")
	audit := AuditServerPluginConfig(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != pcReasonOK {
		t.Fatalf("top level config should scan clean: %+v", audit.Findings)
	}
	if len(audit.Files) != 1 {
		t.Fatalf("expected one file: %v", audit.Files)
	}
}

func TestAuditServerPluginConfigDescribeSummary(t *testing.T) {
	dir := t.TempDir()
	writePC(t, dir, filepath.Join("plugins", "A", "config.yml"), "debug: true\n")
	audit := AuditServerPluginConfig(dir)
	if audit.Describe() == "" || audit.Summary() == "" {
		t.Fatalf("describe/summary empty")
	}
	if len(audit.Codes()) != 1 || audit.Codes()[0] != pcReasonDangerousToggle {
		t.Fatalf("unexpected codes: %v", audit.Codes())
	}
}
