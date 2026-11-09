package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginPermNestedDirectories(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, filepath.Join("Group", "sub"), "config.yml", "permissions:\n  - '*'\n")
	audit := AuditServerPluginPermissions(dir)
	if !plugPermHasReason(audit, plugPermReasonWildcard) {
		t.Fatalf("nested config not scanned: %s", audit.Describe())
	}
}

func TestPluginPermIgnoresUnknownFiles(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "P", "messages.yml", "permissions:\n  - '*'\n")
	audit := AuditServerPluginPermissions(dir)
	if audit.Files != 0 {
		t.Fatalf("unrelated yml scanned: files=%d", audit.Files)
	}
}

func TestPluginPermSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.yml")
	if err := os.WriteFile(target, []byte("permissions:\n  - '*'\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "plugins", "P"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "plugins", "P", "config.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditServerPluginPermissions(dir)
	if !audit.Blocking() || !plugPermHasReason(audit, plugPermReasonUnreadable) {
		t.Fatalf("symlinked config must block: %s", audit.Describe())
	}
}

func TestPluginPermOversizedFileBlocks(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("a", plugPermMaxFileBytes+1)
	writePluginConfig(t, dir, "P", "config.yml", body)
	audit := AuditServerPluginPermissions(dir)
	if !audit.Blocking() || !plugPermHasReason(audit, plugPermReasonTooLarge) {
		t.Fatalf("oversized config must block: %s", audit.Describe())
	}
}

func TestPluginPermPackFormatIgnored(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "P", "config.yml", "permissions:\n  default: member\n  nodes:\n    - \"essentials.home\"\n")
	audit := AuditServerPluginPermissions(dir)
	if !plugPermHasReason(audit, plugPermReasonEveryPermission) {
		t.Fatalf("permissions section not surfaced: %s", audit.Describe())
	}
	if plugPermHasReason(audit, plugPermReasonWildcard) || plugPermHasReason(audit, plugPermReasonOpDefault) {
		t.Fatalf("safe permissions misclassified: %s", audit.Describe())
	}
}

func TestPluginPermSummaryAndCodes(t *testing.T) {
	audit := PluginPermissionAudit{Dir: "x"}
	audit.add("plugins/A/config.yml", 3, plugPermReasonWildcard, "star", true)
	audit.add("plugins/A/config.yml", 5, plugPermReasonOpDefault, "op", false)
	codes := audit.Codes()
	if len(codes) != 2 || codes[0] != plugPermReasonOpDefault {
		t.Fatalf("codes wrong: %v", codes)
	}
	summary := audit.Summary()
	if !strings.Contains(summary, "blocking=1") || !strings.Contains(summary, "warnings=1") {
		t.Fatalf("summary wrong: %s", summary)
	}
	if !strings.Contains(audit.Describe(), "config.yml:3") {
		t.Fatalf("describe wrong: %s", audit.Describe())
	}
}

func TestPluginPermFileBudget(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writePluginConfig(t, dir, filepath.Join("P", strings.Repeat("x", 1)+string(rune('a'+i))), "config.yml", "a: b\n")
	}
	audit := AuditServerPluginPermissions(dir)
	if audit.Files != 5 || audit.Blocking() {
		t.Fatalf("file budget noise: %s", audit.Describe())
	}
}
