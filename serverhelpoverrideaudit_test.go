package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func hoHas(a HelpOverrideAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestHelpOverrideClean(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  rules:\n    shortText: 规则\n    fullText: 请遵守服务器规则\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if a.Blocking() {
		t.Fatalf("干净帮助配置被阻断: %s", a.Describe())
	}
	if a.Topics != 1 {
		t.Fatalf("期望 1 个主题，得到 %d", a.Topics)
	}
}

func TestHelpOverrideMissingDir(t *testing.T) {
	a := AuditServerHelpOverride(filepath.Join(t.TempDir(), "absent"))
	if !hoHas(a, hoReasonMissing) {
		t.Fatalf("期望 missing，得到 %s", a.Describe())
	}
}

func TestHelpOverrideSymlink(t *testing.T) {
	dir := t.TempDir()
	target := auditWriteFileMode(t, dir, "real.yml", "general-topics:\n", 0o600)
	if err := os.Symlink(target, filepath.Join(dir, "help.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestHelpOverrideWorldWritable(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "help.yml", "general-topics:\n", 0o666)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonWorldWritable) {
		t.Fatalf("期望 world-writable，得到 %s", a.Describe())
	}
}

func TestHelpOverrideTooLarge(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "help.yml", strings.Repeat("# pad\n", 200000), 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望 too-large 阻断，得到 %s", a.Describe())
	}
}

func TestHelpOverrideTooManyTopics(t *testing.T) {
	dir := t.TempDir()
	var body strings.Builder
	body.WriteString("general-topics:\n")
	for i := 0; i < hoMaxTopics+2; i++ {
		body.WriteString("  topic")
		body.WriteString(string(rune('a' + i%26)))
		body.WriteString(":\n    shortText: x\n")
	}
	auditWriteFileMode(t, dir, "help.yml", body.String(), 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonTooManyTopics) || !a.Blocking() {
		t.Fatalf("期望 too-many-topics 阻断，得到 %s", a.Describe())
	}
}

func TestHelpOverrideTextTooLong(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  long:\n    shortText: 短\n    fullText: " + strings.Repeat("长", hoMaxFullText+8) + "\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonTextTooLong) || !a.Blocking() {
		t.Fatalf("期望 text-too-long 阻断，得到 %s", a.Describe())
	}
}

func TestHelpOverrideControlChars(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  esc:\n    shortText: bad\u0007text\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonControlChars) {
		t.Fatalf("期望 control-chars，得到 %s", a.Describe())
	}
}

func TestHelpOverrideRemoteURL(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  qq:\n    shortText: 加群 https://example.com/join\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonRemoteURL) {
		t.Fatalf("期望 remote-url，得到 %s", a.Describe())
	}
}

func TestHelpOverrideWildcardPermission(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  admin:\n    shortText: 管理\n    permission: \"*\"\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonWildcardPerm) {
		t.Fatalf("期望 wildcard-permission，得到 %s", a.Describe())
	}
}

func TestHelpOverrideShadowTopic(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  plugins:\n    shortText: 假插件列表\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonShadowTopic) {
		t.Fatalf("期望 shadowed-topic，得到 %s", a.Describe())
	}
}

func TestHelpOverrideBlockScalar(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  rules:\n    fullText: |-\n      第一行\n      第二行\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if a.Blocking() || a.Topics != 1 {
		t.Fatalf("块标量被判异常: %s", a.Describe())
	}
}

func TestHelpOverrideUnknownField(t *testing.T) {
	dir := t.TempDir()
	body := "general-topics:\n  rules:\n    color: red\n"
	auditWriteFileMode(t, dir, "help.yml", body, 0o600)
	a := AuditServerHelpOverride(dir)
	if !hoHas(a, hoReasonUnknownField) {
		t.Fatalf("期望 unknown-field，得到 %s", a.Describe())
	}
}

func TestHelpOverrideConfigVariant(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileMode(t, dir, "config/help.yml", "general-topics:\n  tips:\n    shortText: 提示\n", 0o600)
	a := AuditServerHelpOverride(dir)
	if a.Topics != 1 {
		t.Fatalf("期望读取 config/help.yml，得到 %d 个主题", a.Topics)
	}
}
