package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
