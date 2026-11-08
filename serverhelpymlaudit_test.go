package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shyWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func shyHas(findings []HelpYmlFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestHelpMissingFile(t *testing.T) {
	a := AuditServerHelpYml(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少 help.yml 不应报警: %v", a.Describe())
	}
}

func TestHelpClean(t *testing.T) {
	dir := t.TempDir()
	shyWriteFile(t, dir, "help.yml", "general-topics:\n  default:\n    - shortText: '欢迎'\n      fullText: '欢迎来到服务器'\n")
	a := AuditServerHelpYml(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合法帮助配置不应报警: %v", a.Describe())
	}
}

func TestHelpUnsafeTag(t *testing.T) {
	dir := t.TempDir()
	shyWriteFile(t, dir, "help.yml", "general-topics:\n  default:\n    - shortText: !!javax.script.ScriptEngineManager\n")
	a := AuditServerHelpYml(dir)
	if !a.Blocking() || !shyHas(a.Findings, shyReasonTag) {
		t.Fatalf("危险 YAML 标签应阻断: %v", a.Describe())
	}
}

func TestHelpControlChars(t *testing.T) {
	dir := t.TempDir()
	shyWriteFile(t, dir, "help.yml", "general-topics:\n  default:\n    - shortText: '\u0007'\n")
	a := AuditServerHelpYml(dir)
	if !a.Blocking() || !shyHas(a.Findings, shyReasonCtl) {
		t.Fatalf("控制字符应阻断: %v", a.Describe())
	}
}

func TestHelpObfuscated(t *testing.T) {
	dir := t.TempDir()
	shyWriteFile(t, dir, "help.yml", "general-topics:\n  default:\n    - shortText: '&k隐藏文本'\n")
	a := AuditServerHelpYml(dir)
	if a.Blocking() || !shyHas(a.Findings, shyReasonObfus) {
		t.Fatalf("混淆格式码应告警: %v", a.Describe())
	}
}

func TestHelpTooManyTopics(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("general-topics:\n")
	for i := 0; i < 140; i++ {
		b.WriteString("  topic")
		b.WriteString(strings.Repeat("x", 1))
		b.WriteString(":\n    - shortText: 'ok'\n")
	}
	shyWriteFile(t, dir, "help.yml", b.String())
	a := AuditServerHelpYml(dir)
	if a.Blocking() || !shyHas(a.Findings, shyReasonTopic) {
		t.Fatalf("条目过多应告警: %v", a.Describe())
	}
}

func TestHelpSymlink(t *testing.T) {
	dir := t.TempDir()
	shyWriteFile(t, dir, "real.yml", "general-topics: {}\n")
	if err := os.Symlink(filepath.Join(dir, "real.yml"), filepath.Join(dir, "help.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerHelpYml(dir)
	if !a.Blocking() || !shyHas(a.Findings, shyReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
