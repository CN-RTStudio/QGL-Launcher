package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func pjsJar(t *testing.T, dir, name string, entries map[string]string) {
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

func pjsRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pjsHas(a *PjsAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPluginSignatureSigned(t *testing.T) {
	root, dir := pjsRoot(t)
	pjsJar(t, dir, "a.jar", map[string]string{
		"META-INF/MANIFEST.MF": "x",
		"META-INF/SIGNER.SF":   "y",
		"META-INF/SIGNER.RSA":  "z",
		"com/x/A.class":        "c",
	})
	a := AuditPluginJarSignatures(root)
	if a.HasWarnings() || a.Signed != 1 {
		t.Fatalf("完整签名不应告警: %v", a.Describe())
	}
}

func TestPluginSignatureUnsigned(t *testing.T) {
	root, dir := pjsRoot(t)
	pjsJar(t, dir, "a.jar", map[string]string{"com/x/A.class": "c"})
	a := AuditPluginJarSignatures(root)
	if !pjsHas(a, pjsUnsigned) {
		t.Fatalf("未签名插件应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("未签名属提示项，不应阻断: %v", a.Describe())
	}
}

func TestPluginSignaturePartial(t *testing.T) {
	root, dir := pjsRoot(t)
	pjsJar(t, dir, "a.jar", map[string]string{"META-INF/SIGNER.SF": "y"})
	a := AuditPluginJarSignatures(root)
	if !pjsHas(a, pjsPartial) || !a.Blocking() {
		t.Fatalf("缺签名块应阻断: %v", a.Describe())
	}
}

func TestPluginSignatureEc(t *testing.T) {
	root, dir := pjsRoot(t)
	pjsJar(t, dir, "a.jar", map[string]string{
		"META-INF/SIGNER.SF": "y",
		"META-INF/SIGNER.EC": "z",
	})
	a := AuditPluginJarSignatures(root)
	if a.HasWarnings() {
		t.Fatalf("EC 签名应视为完整: %v", a.Describe())
	}
}

func TestPluginSignatureMissingDir(t *testing.T) {
	a := AuditPluginJarSignatures(t.TempDir())
	if !pjsHas(a, pjsMiss) {
		t.Fatalf("缺少目录应提示: %v", a.Describe())
	}
}

func TestPluginSignatureEmptyArg(t *testing.T) {
	a := AuditPluginJarSignatures("")
	if !pjsHas(a, pjsMiss) {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestPluginSignatureBrokenJar(t *testing.T) {
	root, dir := pjsRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginJarSignatures(root)
	if !pjsHas(a, pjsJarOpen) || !a.Blocking() {
		t.Fatalf("损坏 jar 应阻断: %v", a.Describe())
	}
}

func TestPluginSignatureNonJarIgnored(t *testing.T) {
	root, dir := pjsRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginJarSignatures(root)
	if a.HasWarnings() || a.Jars != 0 {
		t.Fatalf("非 jar 不应参与审计: %v", a.Describe())
	}
}

func TestPluginSignatureDescribe(t *testing.T) {
	root, dir := pjsRoot(t)
	pjsJar(t, dir, "a.jar", map[string]string{"com/x/A.class": "c"})
	if AuditPluginJarSignatures(root).Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}
