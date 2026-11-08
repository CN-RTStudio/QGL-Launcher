package main

import (
	"os"
	"path/filepath"
	"testing"
)

func scyWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func scyHas(findings []CommandsYmlFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAliasMissingFile(t *testing.T) {
	a := AuditServerCommandsYml(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少 commands.yml 不应报警: %v", a.Describe())
	}
}

func TestAliasClean(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "commands.yml", "aliases:\n  spawn:\n    - spawn\n  home:\n    - home\n")
	a := AuditServerCommandsYml(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合法别名不应报警: %v", a.Describe())
	}
}

func TestAliasPrivileged(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "commands.yml", "aliases:\n  givepower:\n    - op Notch\n")
	a := AuditServerCommandsYml(dir)
	if !a.Blocking() || !scyHas(a.Findings, scyReasonPriv) {
		t.Fatalf("高权限别名应阻断: %v", a.Describe())
	}
}

func TestAliasChaining(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "commands.yml", "aliases:\n  combo:\n    - say hi; op Notch\n")
	a := AuditServerCommandsYml(dir)
	if !a.Blocking() || !scyHas(a.Findings, scyReasonChain) {
		t.Fatalf("命令连接符应阻断: %v", a.Describe())
	}
}

func TestAliasBadName(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "commands.yml", "aliases:\n  1bad:\n    - say hi\n")
	a := AuditServerCommandsYml(dir)
	if !a.Blocking() || !scyHas(a.Findings, scyReasonName) {
		t.Fatalf("非法别名应阻断: %v", a.Describe())
	}
}

func TestAliasWithoutCommand(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "commands.yml", "aliases:\n  empty:\n")
	a := AuditServerCommandsYml(dir)
	if a.Blocking() || !scyHas(a.Findings, scyReasonMeth) {
		t.Fatalf("空别名应告警: %v", a.Describe())
	}
}

func TestAliasControlChars(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "commands.yml", "aliases:\n  evil:\n    - say hi\u0007\n")
	a := AuditServerCommandsYml(dir)
	if !a.Blocking() || !scyHas(a.Findings, scyReasonCtl) {
		t.Fatalf("控制字符应阻断: %v", a.Describe())
	}
}

func TestAliasSymlink(t *testing.T) {
	dir := t.TempDir()
	scyWriteFile(t, dir, "real.yml", "aliases:\n")
	if err := os.Symlink(filepath.Join(dir, "real.yml"), filepath.Join(dir, "commands.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerCommandsYml(dir)
	if !a.Blocking() || !scyHas(a.Findings, scyReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
