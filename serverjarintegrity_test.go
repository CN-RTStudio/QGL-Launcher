package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeJarFixture(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("写入测试 JAR 失败: %v", err)
	}
	return path
}

func jarBytes(central bool) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{'P', 'K', 3, 4})
	buf.Write(bytes.Repeat([]byte{0}, 64))
	if central {
		buf.Write([]byte{'P', 'K', 5, 6})
		buf.Write(bytes.Repeat([]byte{0}, 18))
	}
	return buf.Bytes()
}

func zipJarBytes(t *testing.T, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("创建 ZIP 条目失败: %v", err)
		}
		if _, err := entry.Write([]byte("stub")); err != nil {
			t.Fatalf("写入 ZIP 条目失败: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 ZIP 失败: %v", err)
	}
	return buf.Bytes()
}

func TestAuditServerJarAcceptsZipWithSidecar(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "1.21-server.jar", zipJarBytes(t, "META-INF/MANIFEST.MF", "net/minecraft/server/Main.class"))
	audit, err := AuditServerJar(path, func(string) (bool, bool) { return true, true })
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonOK || audit.Blocking() {
		t.Fatalf("期望通过，实际 %s", audit.Reason)
	}
	if !audit.ZipHeader || !audit.ZipCentralDir || !audit.SidecarOK {
		t.Fatalf("结构标记不完整: %+v", audit)
	}
}

func TestAuditServerJarMissingFile(t *testing.T) {
	audit, err := AuditServerJar(filepath.Join(t.TempDir(), "absent.jar"), nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonMissing || !audit.Blocking() {
		t.Fatalf("期望 missing，实际 %s", audit.Reason)
	}
}

func TestAuditServerJarRejectsHtmlBody(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "evil.jar", []byte("<html><body>404</body></html>"))
	audit, err := AuditServerJar(path, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonNotZip || !audit.Blocking() {
		t.Fatalf("期望 not-zip，实际 %s", audit.Reason)
	}
}

func TestAuditServerJarRejectsEmptyAndTruncatedZip(t *testing.T) {
	dir := t.TempDir()
	empty := writeJarFixture(t, dir, "empty.jar", nil)
	audit, err := AuditServerJar(empty, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonEmpty || !audit.Blocking() {
		t.Fatalf("期望 empty，实际 %s", audit.Reason)
	}
	truncated := writeJarFixture(t, dir, "truncated.jar", jarBytes(false))
	audit, err = AuditServerJar(truncated, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonNoCentralDir || !audit.Blocking() {
		t.Fatalf("期望 no-central-directory，实际 %s", audit.Reason)
	}
}

func TestAuditServerJarSidecarMismatchBlocks(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "tampered.jar", zipJarBytes(t))
	audit, err := AuditServerJar(path, func(string) (bool, bool) { return false, true })
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonSidecarMismatch || !audit.Blocking() {
		t.Fatalf("期望 sidecar-mismatch，实际 %s", audit.Reason)
	}
}
