package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func baselineDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("写入 %s 失败: %v", name, err)
		}
	}
	return dir
}

func baselineStorePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "baseline.json")
}

func TestAuditServerConfigBaselineCreates(t *testing.T) {
	dir := baselineDir(t, map[string]string{"server.properties": "online-mode=true\n", "ops.json": "[]"})
	path := baselineStorePath(t)
	audit, err := AuditServerConfigBaseline(dir, path)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Created || len(audit.Findings) != 0 {
		t.Fatalf("首次应创建基线且无差异: %v", audit.Describe())
	}
	if len(audit.Hashes) != 2 {
		t.Fatalf("应记录两个文件摘要，实际 %d", len(audit.Hashes))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("基线文件未落盘: %v", err)
	}
}

func TestAuditServerConfigBaselineStable(t *testing.T) {
	dir := baselineDir(t, map[string]string{"server.properties": "online-mode=true\n"})
	path := baselineStorePath(t)
	if _, err := AuditServerConfigBaseline(dir, path); err != nil {
		t.Fatalf("首次审计失败: %v", err)
	}
	audit, err := AuditServerConfigBaseline(dir, path)
	if err != nil {
		t.Fatalf("二次审计失败: %v", err)
	}
	if audit.Created || len(audit.Findings) != 0 {
		t.Fatalf("文件未变不应报告差异: %v", audit.Describe())
	}
}

func TestAuditServerConfigBaselineModified(t *testing.T) {
	dir := baselineDir(t, map[string]string{"ops.json": "[]"})
	path := baselineStorePath(t)
	if _, err := AuditServerConfigBaseline(dir, path); err != nil {
		t.Fatalf("首次审计失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ops.json"), []byte(`[{"uuid":"x"}]`), 0o600); err != nil {
		t.Fatalf("改写文件失败: %v", err)
	}
	audit, err := AuditServerConfigBaseline(dir, path)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != baselineReasonModified {
		t.Fatalf("应报告修改: %v", audit.Describe())
	}
}

func TestAuditServerConfigBaselineRemoved(t *testing.T) {
	dir := baselineDir(t, map[string]string{"whitelist.json": "[]", "server.properties": "a=b\n"})
	path := baselineStorePath(t)
	if _, err := AuditServerConfigBaseline(dir, path); err != nil {
		t.Fatalf("首次审计失败: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "whitelist.json")); err != nil {
		t.Fatalf("删除文件失败: %v", err)
	}
	audit, err := AuditServerConfigBaseline(dir, path)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != baselineReasonRemoved {
		t.Fatalf("应报告删除: %v", audit.Describe())
	}
}

func TestAuditServerConfigBaselineAdded(t *testing.T) {
	dir := baselineDir(t, map[string]string{"server.properties": "a=b\n"})
	path := baselineStorePath(t)
	if _, err := AuditServerConfigBaseline(dir, path); err != nil {
		t.Fatalf("首次审计失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "banned-ips.json"), []byte("[]"), 0o600); err != nil {
		t.Fatalf("新增文件失败: %v", err)
	}
	audit, err := AuditServerConfigBaseline(dir, path)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != baselineReasonAdded {
		t.Fatalf("应报告新增: %v", audit.Describe())
	}
}

func TestAuditServerConfigBaselineCorruptRebuild(t *testing.T) {
	dir := baselineDir(t, map[string]string{"server.properties": "a=b\n"})
	path := baselineStorePath(t)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("写入坏基线失败: %v", err)
	}
	audit, err := AuditServerConfigBaseline(dir, path)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), baselineReasonCorrupt) {
		t.Fatalf("应报告基线损坏: %v", audit.Codes())
	}
}

func TestAuditServerConfigBaselineSkipsSymlink(t *testing.T) {
	dir := baselineDir(t, map[string]string{"server.properties": "a=b\n"})
	outside := filepath.Join(t.TempDir(), "ops.json")
	if err := os.WriteFile(outside, []byte("[]"), 0o600); err != nil {
		t.Fatalf("写入外部文件失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ops.json")); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditServerConfigBaseline(dir, baselineStorePath(t))
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if _, ok := audit.Hashes["ops.json"]; ok {
		t.Fatalf("符号链接不应进入基线摘要")
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), baselineReasonUnreadable) {
		t.Fatalf("应报告跳过符号链接: %v", audit.Codes())
	}
}
