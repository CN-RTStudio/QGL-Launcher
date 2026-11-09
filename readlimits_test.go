package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditTextReadMaxBytesMatchesReadBoundedFileMinimum(t *testing.T) {
	if auditTextReadMaxBytes <= 0 {
		t.Fatalf("auditTextReadMaxBytes 必须为正，实际 %d", auditTextReadMaxBytes)
	}
	if auditTextReadMaxBytes > localTextConfigMaxBytes {
		t.Fatalf("审计读取上限 %d 不应超过通用文本配置上限 %d", auditTextReadMaxBytes, localTextConfigMaxBytes)
	}
}

func TestReadBoundedFileUsesAuditLimit(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "oversized.conf")
	payload := strings.Repeat("a", int(auditTextReadMaxBytes)+1)
	if err := os.WriteFile(big, []byte(payload), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	data, err := readBoundedFile(big, auditTextReadMaxBytes)
	if err == nil {
		t.Fatalf("超限文件应被拒绝，实际读到 %d 字节", len(data))
	}
	if !errors.Is(err, errLocalFileTooLarge) {
		t.Fatalf("超限错误应为 errLocalFileTooLarge，实际 %v", err)
	}
}

func TestReadBoundedFileAcceptsSmallAuditConfig(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(small, []byte("max-players=20\n"), 0o600); err != nil {
		t.Fatalf("写入测试文件失败: %v", err)
	}
	data, err := readBoundedFile(small, auditTextReadMaxBytes)
	if err != nil {
		t.Fatalf("正常配置读取失败: %v", err)
	}
	if string(data) != "max-players=20\n" {
		t.Fatalf("读取内容不一致: %q", string(data))
	}
}
