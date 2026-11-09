package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
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

func TestAuditServerJarMissingSidecarOnlyWarns(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "fresh.jar", zipJarBytes(t))
	audit, err := AuditServerJar(path, func(string) (bool, bool) { return false, false })
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || len(audit.Warnings) == 0 {
		t.Fatalf("缺侧车应只告警: %+v", audit)
	}
}

func TestAuditServerJarRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := writeJarFixture(t, dir, "real.jar", zipJarBytes(t))
	link := filepath.Join(dir, "link.jar")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("当前平台不支持符号链接: %v", err)
	}
	audit, err := AuditServerJar(link, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Symlink || audit.Reason != serverJarReasonSymlink || !audit.Blocking() {
		t.Fatalf("期望拒绝符号链接: %+v", audit)
	}
}

func TestAuditServerJarRejectsTraversalEntry(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "traversal.jar", zipJarBytes(t, "META-INF/MANIFEST.MF", "../../evil.class"))
	audit, err := AuditServerJar(path, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonSuspiciousEntry || !audit.Blocking() {
		t.Fatalf("期望拒绝越界条目，实际 %s", audit.Reason)
	}
	if len(audit.Suspicious) == 0 || audit.Entries != 2 {
		t.Fatalf("可疑条目未被记录: %+v", audit)
	}
}

func TestAuditServerJarRejectsAbsoluteAndBackslashEntry(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "abs.jar", zipJarBytes(t, "/etc/passwd"))
	audit, err := AuditServerJar(path, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonSuspiciousEntry || !audit.Blocking() {
		t.Fatalf("期望拒绝绝对路径条目，实际 %s", audit.Reason)
	}
	if suspiciousServerJarEntry("C:\\Windows\\x.dll") != true {
		t.Fatalf("盘符条目未被判定为可疑")
	}
}

func TestDescribeServerJarAuditMentionsSize(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "ok.jar", zipJarBytes(t))
	audit, err := AuditServerJar(path, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	text := describeServerJarAudit(audit)
	if text == "" || !bytes.Contains([]byte(text), []byte("字节")) {
		t.Fatalf("描述缺少大小信息: %s", text)
	}
}

func TestAuditServerJarRejectsCorruptContainer(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	buf.Write([]byte{'P', 'K', 3, 4})
	buf.Write(bytes.Repeat([]byte{0}, 64))
	buf.Write([]byte{'P', 'K', 5, 6})
	buf.Write(bytes.Repeat([]byte{0}, 64))
	path := writeJarFixture(t, dir, "corrupt.jar", buf.Bytes())
	audit, err := AuditServerJar(path, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != serverJarReasonCorruptZip || !audit.Blocking() {
		t.Fatalf("期望拒绝无法解析的 ZIP，实际 %s", audit.Reason)
	}
}

func TestDescribeServerJarAuditMentionsEntryCount(t *testing.T) {
	dir := t.TempDir()
	path := writeJarFixture(t, dir, "count.jar", zipJarBytes(t, "a.txt", "b.txt"))
	audit, err := AuditServerJar(path, nil)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	text := describeServerJarAudit(audit)
	if !strings.Contains(text, "条目 2 个") {
		t.Fatalf("描述缺少条目数: %s", text)
	}
}
