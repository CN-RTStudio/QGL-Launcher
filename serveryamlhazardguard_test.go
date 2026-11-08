package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func yhWrite(t *testing.T, dir, name, body string, mode os.FileMode) string {
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

func yhHas(a YamlHazardAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestYamlHazardClean(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "plugin.yml", "name: Demo\nversion: 1.0\n", 0o600)
	a := AuditServerYamlHazards(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("期望无风险，得到 %s", a.Describe())
	}
}

func TestYamlHazardUnsafeTag(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "config.yml", "value: !!javax.script.ScriptEngineManager [x]\n", 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonUnsafeTag) || !a.Blocking() {
		t.Fatalf("期望 unsafe-tag 阻断，得到 %s", a.Describe())
	}
}

func TestYamlHazardObjectApply(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "config/app.yml", "payload: !!python/object/apply:os.system [echo hi]\n", 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonObjectApply) || !a.Blocking() {
		t.Fatalf("期望 object-apply 阻断，得到 %s", a.Describe())
	}
}

func TestYamlHazardAliasBomb(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("root: &seed value\n")
	for i := 0; i < 60; i++ {
		b.WriteString("child: *seed\n")
	}
	yhWrite(t, dir, "config.yml", b.String(), 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonAliasBomb) {
		t.Fatalf("期望 alias-bomb，得到 %s", a.Describe())
	}
}

func TestYamlHazardTabIndent(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "config.yml", "root:\n\tnested: 1\n", 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonTabIndent) {
		t.Fatalf("期望 tab-indent，得到 %s", a.Describe())
	}
}

func TestYamlHazardDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "config.yml", "name: one\nname: two\n", 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonDuplicateKey) {
		t.Fatalf("期望 duplicate-key，得到 %s", a.Describe())
	}
}

func TestYamlHazardBinaryBlob(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "config.yml", "blob: !!binary aGVsbG8=\n", 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonBinaryBlob) && !yhHas(a, yhReasonUnsafeTag) {
		t.Fatalf("期望 binary 或 unsafe tag，得到 %s", a.Describe())
	}
}

func TestYamlHazardSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(target, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "config.yml")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestYamlHazardWorldWritable(t *testing.T) {
	dir := t.TempDir()
	yhWrite(t, dir, "config.yml", "name: demo\n", 0o666)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("期望 world-writable 阻断，得到 %s", a.Describe())
	}
}

func TestYamlHazardTooLarge(t *testing.T) {
	dir := t.TempDir()
	body := "name: demo\n" + strings.Repeat("filler: x\n", (1<<20)/9+2)
	yhWrite(t, dir, "config.yml", body, 0o600)
	a := AuditServerYamlHazards(dir)
	if !yhHas(a, yhReasonTooLarge) {
		t.Fatalf("期望 too-large，得到 %s", a.Describe())
	}
}

func TestYamlHazardNoFiles(t *testing.T) {
	a := AuditServerYamlHazards(t.TempDir())
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("无 YAML 时不应告警，得到 %s", a.Describe())
	}
}
