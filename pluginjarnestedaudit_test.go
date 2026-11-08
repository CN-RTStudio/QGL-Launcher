package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pjnJar(t *testing.T, dir, name string, entries map[string]string) {
	t.Helper()
	path := filepath.Join(dir, name)
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w := zip.NewWriter(out)
	for entry, body := range entries {
		f, err := w.Create(entry)
		if err != nil {
			t.Fatalf("entry: %v", err)
		}
		if _, err := f.Write([]byte(body)); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out.Close()
}

func pjnRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pjnHas(a *PjnAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPluginNestedClean(t *testing.T) {
	root, dir := pjnRoot(t)
	pjnJar(t, dir, "a.jar", map[string]string{"META-INF/MANIFEST.MF": "x", "com/x/A.class": "y"})
	a := AuditPluginNestedJars(root)
	if a.HasWarnings() || a.Nested != 0 {
		t.Fatalf("普通插件不应提示嵌套: %v", a.Describe())
	}
}

func TestPluginNestedEmbedded(t *testing.T) {
	root, dir := pjnRoot(t)
	pjnJar(t, dir, "a.jar", map[string]string{"lib/inner.jar": "PK"})
	a := AuditPluginNestedJars(root)
	if !pjnHas(a, pjnNested) || a.Nested != 1 {
		t.Fatalf("应发现内嵌 jar: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("内嵌 jar 属提示项，不应阻断: %v", a.Describe())
	}
}

func TestPluginNestedMetaInfIgnored(t *testing.T) {
	root, dir := pjnRoot(t)
	pjnJar(t, dir, "a.jar", map[string]string{"META-INF/versions/inner.jar": "PK"})
	a := AuditPluginNestedJars(root)
	if pjnHas(a, pjnNested) {
		t.Fatalf("META-INF 下条目不应算作嵌套插件: %v", a.Describe())
	}
}

func TestPluginNestedTraversal(t *testing.T) {
	root, dir := pjnRoot(t)
	pjnJar(t, dir, "a.jar", map[string]string{"../evil.jar": "PK"})
	a := AuditPluginNestedJars(root)
	if !pjnHas(a, pjnTraversal) || !a.Blocking() {
		t.Fatalf("穿越条目应阻断: %v", a.Describe())
	}
}

func TestPluginNestedMissingDir(t *testing.T) {
	a := AuditPluginNestedJars(t.TempDir())
	if !pjnHas(a, pjnMiss) {
		t.Fatalf("缺少目录应提示: %v", a.Describe())
	}
}

func TestPluginNestedEmptyArg(t *testing.T) {
	a := AuditPluginNestedJars("")
	if !pjnHas(a, pjnMiss) {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestPluginNestedBrokenJar(t *testing.T) {
	root, dir := pjnRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginNestedJars(root)
	if !pjnHas(a, pjnJarOpen) || !a.Blocking() {
		t.Fatalf("损坏 jar 应阻断: %v", a.Describe())
	}
}

func TestPluginNestedNonJarIgnored(t *testing.T) {
	root, dir := pjnRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginNestedJars(root)
	if a.HasWarnings() || a.Jars != 0 {
		t.Fatalf("非 jar 不应参与审计: %v", a.Describe())
	}
}

func TestPluginNestedDescribe(t *testing.T) {
	root, dir := pjnRoot(t)
	pjnJar(t, dir, "a.jar", map[string]string{"x/inner.jar": "PK"})
	if AuditPluginNestedJars(root).Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}
