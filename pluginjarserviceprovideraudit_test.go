package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pjpJar(t *testing.T, dir, name string, entries map[string]string) {
	t.Helper()
	out, err := os.Create(filepath.Join(dir, name))
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

func pjpRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pjpHas(a *PjpAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestServiceClean(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "com.x.impl.ServiceImpl\n",
		"com/x/impl/ServiceImpl.class":    "c",
	})
	a := AuditPluginServiceProviders(root)
	if a.HasWarnings() || a.Providers != 1 || a.Services != 1 {
		t.Fatalf("合法声明不应告警: %v", a.Describe())
	}
}

func TestServiceBadName(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/../evil": "",
	})
	a := AuditPluginServiceProviders(root)
	if !pjpHas(a, pjpBadService) || !a.Blocking() {
		t.Fatalf("非法服务名应阻断: %v", a.Describe())
	}
}

func TestServiceBadProvider(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "../../../evil/Provider\n",
	})
	a := AuditPluginServiceProviders(root)
	if !pjpHas(a, pjpBadProvider) || !a.Blocking() {
		t.Fatalf("非法提供者名应阻断: %v", a.Describe())
	}
}

func TestServiceMissingProvider(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "com.x.impl.Ghost\n",
		"com/x/Other.class":               "c",
	})
	a := AuditPluginServiceProviders(root)
	if !pjpHas(a, pjpMissing) {
		t.Fatalf("缺失实现应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("缺失实现属提示项: %v", a.Describe())
	}
}

func TestServiceInnerClass(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "com.x.Outer$Inner\n",
		"com/x/Outer.class":               "c",
	})
	a := AuditPluginServiceProviders(root)
	if a.HasWarnings() {
		t.Fatalf("内部类提供者应识别: %v", a.Describe())
	}
}

func TestServiceDuplicate(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "com.x.Impl\ncom.x.Impl\n",
		"com/x/Impl.class":                "c",
	})
	a := AuditPluginServiceProviders(root)
	if !pjpHas(a, pjpDuplicate) {
		t.Fatalf("重复提供者应提示: %v", a.Describe())
	}
}

func TestServiceComments(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "# comment\r\n\r\ncom.x.Impl  # trailing\r\n",
		"com/x/Impl.class":                "c",
	})
	a := AuditPluginServiceProviders(root)
	if a.HasWarnings() || a.Providers != 1 {
		t.Fatalf("注释与空行应忽略: %v", a.Describe())
	}
}

func TestServiceEmpty(t *testing.T) {
	root, dir := pjpRoot(t)
	pjpJar(t, dir, "a.jar", map[string]string{
		"META-INF/services/com.x.Service": "\n#only\n",
	})
	a := AuditPluginServiceProviders(root)
	if !pjpHas(a, pjpEmpty) {
		t.Fatalf("空服务文件应提示: %v", a.Describe())
	}
}

func TestServiceMissingDir(t *testing.T) {
	if !pjpHas(AuditPluginServiceProviders(t.TempDir()), pjpMiss) {
		t.Fatalf("缺少目录应提示")
	}
	if !pjpHas(AuditPluginServiceProviders(""), pjpMiss) {
		t.Fatalf("空参数应提示")
	}
}

func TestServiceBrokenJar(t *testing.T) {
	root, dir := pjpRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginServiceProviders(root)
	if !pjpHas(a, pjpJarOpen) || !a.Blocking() {
		t.Fatalf("损坏 jar 应阻断: %v", a.Describe())
	}
}
