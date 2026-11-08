package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeWorldLevelNameRejectsUnsafe(t *testing.T) {
	cases := []string{"", " ", "..", ".", "../world", "a/b", `a\b`, "C:world", "-x", "a\x00b", "CON", "world.", "world ", strings.Repeat("w", worldMaxNameRunes+1)}
	for _, name := range cases {
		if safeWorldLevelName(name) {
			t.Fatalf("应拒绝 %q", name)
		}
	}
	for _, name := range []string{"world", "world_nether", "存档-1", "w.1"} {
		if !safeWorldLevelName(name) {
			t.Fatalf("应接受 %q", name)
		}
	}
}

func TestAuditWorldPathAcceptsPlainDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "world"), 0o700); err != nil {
		t.Fatalf("创建世界目录失败: %v", err)
	}
	audit, err := AuditWorldPath(dir, "world")
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != worldReasonOK || audit.Blocking() || !audit.Present {
		t.Fatalf("期望通过，实际 %+v", audit)
	}
	if !strings.Contains(describeWorldPathAudit(audit), "目录已存在") {
		t.Fatalf("描述缺少存在标记")
	}
}

func TestAuditWorldPathMissingOnlyWarns(t *testing.T) {
	audit, err := AuditWorldPath(t.TempDir(), "world")
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || len(audit.Warnings) == 0 {
		t.Fatalf("缺失世界目录应仅告警，实际 %+v", audit)
	}
}

func TestAuditWorldPathRejectsTraversalName(t *testing.T) {
	audit, err := AuditWorldPath(t.TempDir(), "../escape")
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != worldReasonUnsafeName || !audit.Blocking() {
		t.Fatalf("期望拒绝越界名，实际 %s", audit.Reason)
	}
}

func TestAuditWorldPathRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "world")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	audit, err := AuditWorldPath(dir, "world")
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != worldReasonSymlink || !audit.Blocking() || !audit.Symlink {
		t.Fatalf("期望拒绝符号链接，实际 %+v", audit)
	}
}

func TestAuditWorldPathRejectsFileOccupyingWorld(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "world"), []byte("x"), 0o600); err != nil {
		t.Fatalf("写入占用文件失败: %v", err)
	}
	audit, err := AuditWorldPath(dir, "world")
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Reason != worldReasonNotDirectory || !audit.Blocking() {
		t.Fatalf("期望拒绝文件占用，实际 %s", audit.Reason)
	}
}

func TestReadWorldLevelNameFromProperties(t *testing.T) {
	dir := t.TempDir()
	content := "# 注释\nlevel-name=safe_world\nmotd=hi\n"
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o600); err != nil {
		t.Fatalf("写入属性失败: %v", err)
	}
	name, ok, err := readWorldLevelName(dir)
	if err != nil || !ok || name != "safe_world" {
		t.Fatalf("读取 level-name 失败: %q %v %v", name, ok, err)
	}
}

func TestReadWorldLevelNameAbsent(t *testing.T) {
	name, ok, err := readWorldLevelName(t.TempDir())
	if err != nil || ok || name != "" {
		t.Fatalf("缺少 properties 时应返回空值: %q %v %v", name, ok, err)
	}
}

func TestReadWorldLevelNameRejectsSymlinkProperties(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(target, []byte("level-name=world\n"), 0o600); err != nil {
		t.Fatalf("写入属性失败: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	if _, _, err := readWorldLevelName(dir); err == nil {
		t.Fatalf("符号链接的 properties 应被拒绝")
	}
}

func TestAuditWorldPathRejectsAbsoluteAndEmptyNames(t *testing.T) {
	for _, name := range []string{"/etc", `\\server\share`, "", "   "} {
		audit, err := AuditWorldPath(t.TempDir(), name)
		if err != nil {
			t.Fatalf("审计 %q 失败: %v", name, err)
		}
		if !audit.Blocking() {
			t.Fatalf("应拒绝 %q，实际 %s", name, audit.Reason)
		}
	}
}
