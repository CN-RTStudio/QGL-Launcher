package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pjmJar(t *testing.T, dir, name string, entries map[string]string) {
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

func pjmRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pjmHas(a *PjmAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestManifestClean(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nImplementation-Title: demo\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if a.HasWarnings() || a.Manifests != 1 {
		t.Fatalf("普通清单不应告警: %v", a.Describe())
	}
}

func TestManifestAgent(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nPremain-Class: com.x.Agent\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if !pjmHas(a, pjmAgent) || !a.Blocking() || a.AgentAttrs != 1 {
		t.Fatalf("Premain-Class 应阻断: %v", a.Describe())
	}
}

func TestManifestAgentLauncher(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nLauncher-Agent-Class: com.x.L\r\n\r\n",
	})
	if !pjmHas(AuditPluginManifestTrust(root), pjmAgent) {
		t.Fatalf("Launcher-Agent-Class 应阻断")
	}
}

func TestManifestClassPathRemote(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nClass-Path: https://evil.example/x.jar\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if !pjmHas(a, pjmClassPath) || !a.Blocking() {
		t.Fatalf("远程类路径应阻断: %v", a.Describe())
	}
}

func TestManifestClassPathTraversal(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nClass-Path: ../../lib/evil.jar\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if !pjmHas(a, pjmClassPath) {
		t.Fatalf("路径穿越应阻断: %v", a.Describe())
	}
}

func TestManifestClassPathLocal(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nClass-Path: lib/dep.jar\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if a.Blocking() {
		t.Fatalf("相对本地依赖不阻断: %v", a.Describe())
	}
}

func TestManifestMainClass(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nMain-Class: com.x.Main\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if !pjmHas(a, pjmMainClass) || a.Blocking() {
		t.Fatalf("Main-Class 应为提示项: %v", a.Describe())
	}
}

func TestManifestFoldedValue(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\r\nClass-Path: lib/a.jar\r\n http://evil/x.jar\r\n\r\n",
	})
	a := AuditPluginManifestTrust(root)
	if !pjmHas(a, pjmClassPath) {
		t.Fatalf("折行续行应参与判定: %v", a.Describe())
	}
}

func TestManifestEmptyAndMissing(t *testing.T) {
	root, dir := pjmRoot(t)
	pjmJar(t, dir, "a.jar", map[string]string{"META-INF/MANIFEST.MF": "  \r\n"})
	a := AuditPluginManifestTrust(root)
	if !pjmHas(a, pjmManifestEmpty) {
		t.Fatalf("空清单应提示: %v", a.Describe())
	}
	if !pjmHas(AuditPluginManifestTrust(""), pjmMiss) {
		t.Fatalf("空参数应提示")
	}
}
