package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pcxJar(t *testing.T, dir, name string, entries map[string]string) {
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

func pcxRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pcxHasClass(a *PcxAudit, class string) bool {
	for _, s := range a.Shadows {
		if s.Class == class {
			return true
		}
	}
	return false
}

func TestPluginClassClean(t *testing.T) {
	root, dir := pcxRoot(t)
	pcxJar(t, dir, "a.jar", map[string]string{"com/x/A.class": "x", "META-INF/MANIFEST.MF": "y"})
	a := AuditPluginClassShadow(root)
	if a.HasWarnings() {
		t.Fatalf("单插件不应报警: %v", a.Describe())
	}
	if a.Jars != 1 || a.Classes != 1 {
		t.Fatalf("计数错误 jars=%d classes=%d", a.Jars, a.Classes)
	}
}

func TestPluginClassShadow(t *testing.T) {
	root, dir := pcxRoot(t)
	pcxJar(t, dir, "a.jar", map[string]string{"com/x/A.class": "x"})
	pcxJar(t, dir, "b.jar", map[string]string{"com/x/A.class": "y"})
	a := AuditPluginClassShadow(root)
	if !pcxHasClass(a, "com/x/A.class") {
		t.Fatalf("应发现类遮蔽: %v", a.Describe())
	}
}

func TestPluginClassNoShadowSameJar(t *testing.T) {
	root, dir := pcxRoot(t)
	pcxJar(t, dir, "a.jar", map[string]string{"com/x/A.class": "x"})
	a := AuditPluginClassShadow(root)
	if len(a.Shadows) != 0 {
		t.Fatalf("同一 jar 不应自遮蔽: %v", a.Describe())
	}
}

func TestPluginClassEntryTraversal(t *testing.T) {
	root, dir := pcxRoot(t)
	pcxJar(t, dir, "a.jar", map[string]string{"../evil.class": "x"})
	a := AuditPluginClassShadow(root)
	if !a.HasWarnings() {
		t.Fatalf("目录穿越入口应提示: %v", a.Describe())
	}
}

func TestPluginClassMissingDir(t *testing.T) {
	a := AuditPluginClassShadow(t.TempDir())
	if !a.HasWarnings() {
		t.Fatalf("缺少插件目录应提示: %v", a.Describe())
	}
}

func TestPluginClassEmptyArg(t *testing.T) {
	a := AuditPluginClassShadow("")
	if !a.HasWarnings() {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestPluginClassBrokenJar(t *testing.T) {
	root, dir := pcxRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("not a zip"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginClassShadow(root)
	if !a.Blocking() {
		t.Fatalf("损坏 jar 应阻断: %v", a.Describe())
	}
}

func TestPluginClassNonJarIgnored(t *testing.T) {
	root, dir := pcxRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginClassShadow(root)
	if a.HasWarnings() || a.Jars != 0 {
		t.Fatalf("非 jar 不应参与审计: %v", a.Describe())
	}
}

func TestPluginClassDescribe(t *testing.T) {
	a := AuditPluginClassShadow(t.TempDir())
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}
