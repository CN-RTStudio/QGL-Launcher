package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pjcJar(t *testing.T, dir, name string, entries []struct{ Name, Body string }) {
	t.Helper()
	path := filepath.Join(dir, name)
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := zip.NewWriter(out)
	for _, e := range entries {
		f, err := w.Create(e.Name)
		if err != nil {
			t.Fatalf("entry %q: %v", e.Name, err)
		}
		if _, err := f.Write([]byte(e.Body)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out.Close()
}

func pjcRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pjcHas(a *PjcAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPluginCaseClean(t *testing.T) {
	root, dir := pjcRoot(t)
	pjcJar(t, dir, "a.jar", []struct{ Name, Body string }{
		{"com/x/A.class", "c"},
		{"META-INF/MANIFEST.MF", "m"},
	})
	a := AuditPluginEntryCase(root)
	if a.HasWarnings() || a.Entries != 2 {
		t.Fatalf("普通条目不应告警: %v", a.Describe())
	}
}

func TestPluginCaseClash(t *testing.T) {
	root, dir := pjcRoot(t)
	pjcJar(t, dir, "a.jar", []struct{ Name, Body string }{
		{"com/x/A.class", "c"},
		{"com/x/a.class", "d"},
	})
	a := AuditPluginEntryCase(root)
	if !pjcHas(a, pjcCaseClash) || !a.Blocking() {
		t.Fatalf("仅大小写不同的条目应阻断: %v", a.Describe())
	}
}

func TestPluginCaseDuplicate(t *testing.T) {
	root, dir := pjcRoot(t)
	pjcJar(t, dir, "a.jar", []struct{ Name, Body string }{
		{"com/x/A.class", "c"},
		{"com/x/A.class", "d"},
	})
	a := AuditPluginEntryCase(root)
	if !pjcHas(a, pjcDuplicate) {
		t.Fatalf("同名重复条目应阻断: %v", a.Describe())
	}
}

func TestPluginCaseBackslash(t *testing.T) {
	root, dir := pjcRoot(t)
	pjcJar(t, dir, "a.jar", []struct{ Name, Body string }{
		{"com\\x\\A.class", "c"},
	})
	a := AuditPluginEntryCase(root)
	if !pjcHas(a, pjcBackslash) {
		t.Fatalf("反斜杠条目应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("反斜杠属提示项: %v", a.Describe())
	}
}

func TestPluginCaseControlChar(t *testing.T) {
	root, dir := pjcRoot(t)
	pjcJar(t, dir, "a.jar", []struct{ Name, Body string }{
		{"com/x/A\x00.class", "c"},
	})
	a := AuditPluginEntryCase(root)
	if !pjcHas(a, pjcCtrlReason) || !a.Blocking() {
		t.Fatalf("控制字符条目应阻断: %v", a.Describe())
	}
}

func TestPluginCaseMissingDir(t *testing.T) {
	a := AuditPluginEntryCase(t.TempDir())
	if !pjcHas(a, pjcMiss) {
		t.Fatalf("缺少目录应提示: %v", a.Describe())
	}
}

func TestPluginCaseEmptyArg(t *testing.T) {
	a := AuditPluginEntryCase("")
	if !pjcHas(a, pjcMiss) {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestPluginCaseBrokenJar(t *testing.T) {
	root, dir := pjcRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginEntryCase(root)
	if !pjcHas(a, pjcJarOpen) || !a.Blocking() {
		t.Fatalf("损坏 jar 应阻断: %v", a.Describe())
	}
}

func TestPluginCaseDescribe(t *testing.T) {
	root, dir := pjcRoot(t)
	pjcJar(t, dir, "a.jar", []struct{ Name, Body string }{
		{"com/x/A.class", "c"},
		{"com/x/a.class", "d"},
	})
	if AuditPluginEntryCase(root).Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}
