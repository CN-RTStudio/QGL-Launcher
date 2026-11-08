package main

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func pjvClass(major uint16) []byte {
	buf := make([]byte, 8)
	buf[0] = 0xca
	buf[1] = 0xfe
	buf[2] = 0xba
	buf[3] = 0xbe
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], major)
	return buf
}

func pjvJar(t *testing.T, dir, name string, entries map[string][]byte) {
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
		if _, err := f.Write(body); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	out.Close()
}

func pjvRoot(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "plugins")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func pjvHas(a *PjvAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPluginJarClassClean(t *testing.T) {
	root, dir := pjvRoot(t)
	pjvJar(t, dir, "a.jar", map[string][]byte{
		"com/x/A.class":        pjvClass(52),
		"META-INF/MANIFEST.MF": []byte("m"),
	})
	a := AuditPluginClassVersion(root)
	if a.HasWarnings() || a.Classes != 1 || a.MaxMajor != 52 {
		t.Fatalf("正常 class 不应告警: %v", a.Describe())
	}
}

func TestPluginClassTooNew(t *testing.T) {
	root, dir := pjvRoot(t)
	pjvJar(t, dir, "a.jar", map[string][]byte{"com/x/A.class": pjvClass(69)})
	a := AuditPluginClassVersion(root)
	if !pjvHas(a, pjvTooNew) {
		t.Fatalf("过新版本应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("版本偏高属提示项: %v", a.Describe())
	}
}

func TestPluginClassBadMagic(t *testing.T) {
	root, dir := pjvRoot(t)
	pjvJar(t, dir, "a.jar", map[string][]byte{"com/x/A.class": []byte("notclass")})
	a := AuditPluginClassVersion(root)
	if !pjvHas(a, pjvBadMagic) || !a.Blocking() {
		t.Fatalf("错误魔数应阻断: %v", a.Describe())
	}
}

func TestPluginClassBadVersion(t *testing.T) {
	root, dir := pjvRoot(t)
	pjvJar(t, dir, "a.jar", map[string][]byte{"com/x/A.class": pjvClass(44)})
	a := AuditPluginClassVersion(root)
	if !pjvHas(a, pjvBadVersion) || !a.Blocking() {
		t.Fatalf("版本过低应阻断: %v", a.Describe())
	}
}

func TestPluginClassShortHeader(t *testing.T) {
	root, dir := pjvRoot(t)
	pjvJar(t, dir, "a.jar", map[string][]byte{"com/x/A.class": []byte{0xca, 0xfe}})
	a := AuditPluginClassVersion(root)
	if !pjvHas(a, pjvBadMagic) {
		t.Fatalf("截断文件头应阻断: %v", a.Describe())
	}
}

func TestPluginJarClassMissingDir(t *testing.T) {
	a := AuditPluginClassVersion(t.TempDir())
	if !pjvHas(a, pjvMiss) {
		t.Fatalf("缺少目录应提示: %v", a.Describe())
	}
}

func TestPluginJarClassEmptyArg(t *testing.T) {
	a := AuditPluginClassVersion("")
	if !pjvHas(a, pjvMiss) {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestPluginJarClassBrokenJar(t *testing.T) {
	root, dir := pjvRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "bad.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	a := AuditPluginClassVersion(root)
	if !pjvHas(a, pjvJarOpen) || !a.Blocking() {
		t.Fatalf("损坏 jar 应阻断: %v", a.Describe())
	}
}

func TestPluginJarClassDescribe(t *testing.T) {
	root, dir := pjvRoot(t)
	pjvJar(t, dir, "a.jar", map[string][]byte{"com/x/A.class": pjvClass(69)})
	if AuditPluginClassVersion(root).Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}
