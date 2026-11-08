package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pnhJar(t *testing.T, dir, name string, entries map[string]string) {
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

func pnhRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pnhHas(a *PnhAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPluginNativeClean(t *testing.T) {
	root, dir := pnhRoot(t)
	pnhJar(t, dir, "a.jar", map[string]string{"com/x/A.class": "x"})
	a := AuditPluginNativeExtract(root)
	if a.HasWarnings() {
		t.Fatalf("纯 Java 插件不应报警: %v", a.Describe())
	}
	if a.Jars != 1 {
		t.Fatalf("应统计 1 个 jar，实际 %d", a.Jars)
	}
}

func TestPluginNativeDll(t *testing.T) {
	root, dir := pnhRoot(t)
	pnhJar(t, dir, "a.jar", map[string]string{"native/hook.dll": "MZ"})
	a := AuditPluginNativeExtract(root)
	if !pnhHas(a, pnhNative) || !a.Blocking() {
		t.Fatalf("内嵌 DLL 应阻断: %v", a.Describe())
	}
	if a.Natives != 1 {
		t.Fatalf("应统计 1 个原生二进制，实际 %d", a.Natives)
	}
}

func TestPluginNativeSo(t *testing.T) {
	root, dir := pnhRoot(t)
	pnhJar(t, dir, "a.jar", map[string]string{"lib/libhook.so": "ELF"})
	a := AuditPluginNativeExtract(root)
	if !pnhHas(a, pnhNative) {
		t.Fatalf("内嵌 so 应阻断: %v", a.Describe())
	}
}

func TestPluginNativeScript(t *testing.T) {
	root, dir := pnhRoot(t)
	pnhJar(t, dir, "a.jar", map[string]string{"run.bat": "echo hi"})
	a := AuditPluginNativeExtract(root)
	if !pnhHas(a, pnhScript) || a.Blocking() {
		t.Fatalf("批处理脚本应提示但不阻断: %v", a.Describe())
	}
}

func TestPluginNativeTraversal(t *testing.T) {
	root, dir := pnhRoot(t)
	pnhJar(t, dir, "a.jar", map[string]string{"../../etc/passwd": "x"})
	a := AuditPluginNativeExtract(root)
	if !pnhHas(a, pnhTraversal) || !a.Blocking() {
		t.Fatalf("穿越入口应阻断: %v", a.Describe())
	}
}

func TestPluginNativeMissingDir(t *testing.T) {
	a := AuditPluginNativeExtract(t.TempDir())
	if !pnhHas(a, pnhMiss) {
		t.Fatalf("缺少插件目录应提示: %v", a.Describe())
	}
}

func TestPluginNativeEmptyArg(t *testing.T) {
	a := AuditPluginNativeExtract("")
	if !pnhHas(a, pnhMiss) {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestPluginNativeBrokenJar(t *testing.T) {
	root, dir := pnhRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginNativeExtract(root)
	if !pnhHas(a, pnhJarOpen) {
		t.Fatalf("损坏 jar 应提示: %v", a.Describe())
	}
}

func TestPluginNativeNonJarIgnored(t *testing.T) {
	root, dir := pnhRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "data.dat"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginNativeExtract(root)
	if a.HasWarnings() || a.Jars != 0 {
		t.Fatalf("非 jar 不应参与审计: %v", a.Describe())
	}
}

func TestPluginNativeDescribe(t *testing.T) {
	root, dir := pnhRoot(t)
	pnhJar(t, dir, "a.jar", map[string]string{"x.exe": "MZ"})
	if AuditPluginNativeExtract(root).Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}
