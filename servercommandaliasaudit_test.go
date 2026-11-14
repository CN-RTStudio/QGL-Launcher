package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func caHas(a CommandAliasAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestCommandAliasClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  spawn:\n  - \"spawn\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if a.Blocking() {
		t.Fatalf("干净配置被判定阻断: %s", a.Describe())
	}
}

func TestCommandAliasMissingDir(t *testing.T) {
	a := AuditServerCommandAliases(filepath.Join(t.TempDir(), "absent"))
	if !caHas(a, caReasonMissing) {
		t.Fatalf("期望 missing，得到 %s", a.Describe())
	}
}

func TestCommandAliasSymlink(t *testing.T) {
	dir := t.TempDir()
	target := auditWriteFileMode(t, dir, "real.yml", "aliases:\n", 0o600)
	link := filepath.Join(dir, "commands.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestCommandAliasWorldWritable(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n", 0o666)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonWorldWritable) {
		t.Fatalf("期望 world-writable，得到 %s", a.Describe())
	}
}

func TestCommandAliasCatchAll(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  \"*\":\n  - \"say\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonCatchAll) || !a.Blocking() {
		t.Fatalf("期望 catch-all 阻断，得到 %s", a.Describe())
	}
}

func TestCommandAliasShadowedOp(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  op:\n  - \"version\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonShadowed) || !a.Blocking() {
		t.Fatalf("期望 shadowed 阻断，得到 %s", a.Describe())
	}
}

func TestCommandAliasInternalTarget(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  lucky:\n  - \"bukkit:op\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonInternalTarget) {
		t.Fatalf("期望 internal-target，得到 %s", a.Describe())
	}
}

func TestCommandAliasInlineList(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  kit: [\"give\", \"time set day\"]\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if a.Blocking() {
		t.Fatalf("内联列表被误判: %s", a.Describe())
	}
	if a.Aliases != 1 {
		t.Fatalf("期望 1 个别名，得到 %d", a.Aliases)
	}
}

func TestCommandAliasEmptyTarget(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  ghost:\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonEmptyTarget) {
		t.Fatalf("期望 empty-target，得到 %s", a.Describe())
	}
}

func TestCommandAliasBadName(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  bad name!:\n  - \"say\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonBadName) {
		t.Fatalf("期望 bad-alias-name，得到 %s", a.Describe())
	}
}

func TestCommandAliasTooMany(t *testing.T) {
	dir := t.TempDir()
	var body strings.Builder
	body.WriteString("aliases:\n")
	for i := 0; i < caMaxAliases+2; i++ {
		body.WriteString("  a")
		body.WriteString(string(rune('a' + i%26)))
		body.WriteString("x:\n  - \"say\"\n")
	}
	auditWriteFileMode(t, dir, "commands.yml", body.String(), 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonTooManyAlias) {
		t.Fatalf("期望 too-many-aliases，得到 %s", a.Describe())
	}
}

func TestCommandAliasDuplicateTarget(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  twice:\n  - \"say hi\"\n  - \"say hi\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonDuplicate) {
		t.Fatalf("期望 duplicate-alias，得到 %s", a.Describe())
	}
}

func TestCommandAliasVariableTarget(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "commands.yml", "aliases:\n  who:\n  - \"say $player\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if a.Blocking() {
		t.Fatalf("变量目标不应阻断: %s", a.Describe())
	}
}

func TestCommandAliasTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := "aliases:\n" + strings.Repeat("# padding\n", 300000)
	auditWriteFileMode(t, dir, "commands.yml", body, 0o600)
	a := AuditServerCommandAliases(dir)
	if !caHas(a, caReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望 too-large 阻断，得到 %s", a.Describe())
	}
}

func TestCommandAliasConfigDirVariant(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "config/commands.yml", "aliases:\n  spawn:\n  - \"spawn\"\n", 0o600)
	a := AuditServerCommandAliases(dir)
	if a.Aliases != 1 {
		t.Fatalf("期望读取 config/commands.yml，得到 %d 个别名", a.Aliases)
	}
}
