package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writePluginConfig(t *testing.T, serverDir, plugin, name, body string) {
	t.Helper()
	dir := filepath.Join(serverDir, "plugins", plugin)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func plugPermHasReason(audit PluginPermissionAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPluginPermCleanConfig(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "Essentials", "config.yml", "settings:\n  spawn-monsters: false\n")
	audit := AuditServerPluginPermissions(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("clean config reported: %s", audit.Describe())
	}
	if audit.Files != 1 {
		t.Fatalf("expected one config file, got %d", audit.Files)
	}
}

func TestPluginPermMissingDirectory(t *testing.T) {
	audit := AuditServerPluginPermissions(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() || !plugPermHasReason(audit, plugPermReasonMissing) {
		t.Fatalf("missing server dir must block: %s", audit.Describe())
	}
}

func TestPluginPermNoPluginsDirectory(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerPluginPermissions(dir)
	if audit.Blocking() {
		t.Fatalf("absent plugins dir should not block: %s", audit.Describe())
	}
	if !plugPermHasReason(audit, plugPermReasonMissing) {
		t.Fatal("plugins dir absence not reported")
	}
}

func TestPluginPermWildcardNodeBlocks(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "LuckPerms", "groups.yml", "default:\n  permissions:\n    - '*'\n")
	audit := AuditServerPluginPermissions(dir)
	if !audit.Blocking() || !plugPermHasReason(audit, plugPermReasonWildcard) {
		t.Fatalf("wildcard permission must block: %s", audit.Describe())
	}
}

func TestPluginPermWildcardQuoted(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "Perms", "config.yml", "groups:\n  admin:\n    permissions:\n      - \"*:*\"\n")
	audit := AuditServerPluginPermissions(dir)
	if !plugPermHasReason(audit, plugPermReasonWildcardPlugin) {
		t.Fatalf("wildcard plugin node not flagged: %s", audit.Describe())
	}
}

func TestPluginPermWildcardList(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "Perms", "permissions.yml", "granted:\n  - \"*\", \"*:*\"\n")
	audit := AuditServerPluginPermissions(dir)
	if !plugPermHasReason(audit, plugPermReasonWildcardPlugin) {
		t.Fatalf("wildcard list not flagged: %s", audit.Describe())
	}
}

func TestPluginPermOpDefaultWarning(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "WorldGuard", "config.yml", "permissions:\n  default: op\n")
	audit := AuditServerPluginPermissions(dir)
	if !plugPermHasReason(audit, plugPermReasonOpDefault) {
		t.Fatalf("op default not flagged: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("op default should stay a warning: %s", audit.Describe())
	}
}

func TestPluginPermCommentsIgnored(t *testing.T) {
	dir := t.TempDir()
	writePluginConfig(t, dir, "P", "config.yml", "# permissions:\n#   - '*'\n")
	audit := AuditServerPluginPermissions(dir)
	if audit.Blocking() {
		t.Fatalf("comments must not block: %s", audit.Describe())
	}
	if plugPermHasReason(audit, plugPermReasonWildcard) {
		t.Fatalf("comment wildcard flagged: %s", audit.Describe())
	}
}
