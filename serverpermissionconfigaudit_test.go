package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pmWrite(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func pmHas(a PermissionConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPermissionConfigClean(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "permissions.yml", "demo.use:\n  description: allows demo\n  default: false\n", 0o600)
	a := AuditServerPermissionConfig(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("期望无风险，得到 %s", a.Describe())
	}
}

func TestPermissionConfigWildcard(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "permissions.yml", "*:\n  description: all\n", 0o600)
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonWildcardGrant) || !a.Blocking() {
		t.Fatalf("期望 wildcard-grant 阻断，得到 %s", a.Describe())
	}
}

func TestPermissionConfigDefaultOp(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "permissions.yml", "demo.admin:\n  description: admin\n  default: op\n", 0o600)
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonDefaultOp) {
		t.Fatalf("期望 default-op，得到 %s", a.Describe())
	}
}

func TestPermissionConfigDefaultAllow(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "permissions.yml", "demo.open:\n  description: open\n  default: true\n", 0o600)
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonDefaultAllow) {
		t.Fatalf("期望 default-allow，得到 %s", a.Describe())
	}
}

func TestPermissionConfigOpCommand(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "permissions.yml", "granted:\n  - minecraft.command.op\n", 0o600)
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonOpCommand) {
		t.Fatalf("期望 op-command-grant，得到 %s", a.Describe())
	}
}

func TestPermissionConfigPluginDir(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "plugins/Demo/permissions.yml", "granted:\n  - \"*\n", 0o600)
	a := AuditServerPermissionConfig(dir)
	if len(a.Files) == 0 {
		t.Fatalf("期望扫描到插件权限文件")
	}
}

func TestPermissionConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "permissions.yml")
	if err := os.WriteFile(target, []byte("a.use: {}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "permissions.yml")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestPermissionConfigWorldWritable(t *testing.T) {
	dir := t.TempDir()
	pmWrite(t, dir, "permissions.yml", "a.use:\n  default: false\n", 0o666)
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("期望 world-writable 阻断，得到 %s", a.Describe())
	}
}

func TestPermissionConfigTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := "a.use:\n  default: false\n" + strings.Repeat("filler.use:\n  default: false\n", 60000)
	pmWrite(t, dir, "permissions.yml", body, 0o600)
	a := AuditServerPermissionConfig(dir)
	if !pmHas(a, pmReasonTooLarge) {
		t.Fatalf("期望 too-large，得到 %s", a.Describe())
	}
}

func TestPermissionConfigMissingDir(t *testing.T) {
	a := AuditServerPermissionConfig(filepath.Join(t.TempDir(), "absent"))
	if !a.Blocking() {
		t.Fatalf("期望目录缺失阻断，得到 %s", a.Describe())
	}
}
