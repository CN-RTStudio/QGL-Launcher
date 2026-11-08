package main

import (
	"os"
	"path/filepath"
	"testing"
)

func smnWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "permissions.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func smnHas(findings []PermissionsFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPermissionsClean(t *testing.T) {
	dir := t.TempDir()
	smnWrite(t, dir, "default: false\ngroups:\n  staff:\n    default: false\n    permissions:\n      - bukkit.command.help\nusers:\n  alice:\n    group: staff\n")
	if a := AuditServerPermissions(dir); a.HasWarnings() {
		t.Fatalf("合法权限配置不应报警: %v", a.Describe())
	}
}

func TestPermissionsDefaultOp(t *testing.T) {
	dir := t.TempDir()
	smnWrite(t, dir, "default: op\n")
	a := AuditServerPermissions(dir)
	if !a.Blocking() || !smnHas(a.Findings, smnReasonDefault) {
		t.Fatalf("默认 op 应阻断: %v", a.Describe())
	}
}

func TestPermissionsWildcard(t *testing.T) {
	dir := t.TempDir()
	smnWrite(t, dir, "groups:\n  admin:\n    permissions:\n      - '*'\n")
	a := AuditServerPermissions(dir)
	if !a.Blocking() || !smnHas(a.Findings, smnReasonWild) {
		t.Fatalf("通配权限应阻断: %v", a.Describe())
	}
}

func TestPermissionsOpGrant(t *testing.T) {
	dir := t.TempDir()
	smnWrite(t, dir, "groups:\n  staff:\n    permissions:\n      - bukkit.command.op\n")
	a := AuditServerPermissions(dir)
	if !smnHas(a.Findings, smnReasonOpGrant) {
		t.Fatalf("授予 op 命令应报警: %v", a.Describe())
	}
}

func TestPermissionsInvalidNode(t *testing.T) {
	dir := t.TempDir()
	smnWrite(t, dir, "groups:\n  staff:\n    permissions:\n      - 'bad node'\n")
	a := AuditServerPermissions(dir)
	if !smnHas(a.Findings, smnReasonNode) {
		t.Fatalf("非法节点应报警: %v", a.Describe())
	}
}

func TestPermissionsMissing(t *testing.T) {
	if a := AuditServerPermissions(t.TempDir()); a.Blocking() {
		t.Fatalf("缺少 permissions.yml 不应阻断: %v", a.Describe())
	}
}
