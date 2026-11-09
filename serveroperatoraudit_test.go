package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func TestAuditServerOperatorsClean(t *testing.T) {
	dir := baselineDir(t, map[string]string{
		"ops.json":       `[{"uuid":"0123456789abcdef0123456789abcdef","name":"Alice","level":4,"bypassesPlayerLimit":false}]`,
		"whitelist.json": `[{"uuid":"fedcba9876543210fedcba9876543210","name":"Bob"}]`,
	})
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if len(audit.Findings) != 0 || audit.Blocking() {
		t.Fatalf("干净名单不应有问题: %v", audit.Describe())
	}
	if audit.Files["ops.json"] != 1 {
		t.Fatalf("应统计到 1 个 OP")
	}
}

func TestAuditServerOperatorsDuplicateUUID(t *testing.T) {
	dir := baselineDir(t, map[string]string{
		"ops.json": `[{"uuid":"0123456789abcdef0123456789abcdef","name":"Alice","level":4},{"uuid":"0123456789abcdef0123456789abcdef","name":"Alice2","level":4}]`,
	})
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), operatorReasonDuplicate) {
		t.Fatalf("重复 UUID 应报告: %v", audit.Codes())
	}
}

func TestAuditServerOperatorsBadUUID(t *testing.T) {
	dir := baselineDir(t, map[string]string{
		"whitelist.json": `[{"uuid":"not-a-uuid","name":"Eve"}]`,
	})
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), operatorReasonBadUUID) {
		t.Fatalf("非法 UUID 应报告: %v", audit.Codes())
	}
}

func TestAuditServerOperatorsBadLevel(t *testing.T) {
	dir := baselineDir(t, map[string]string{
		"ops.json": `[{"uuid":"0123456789abcdef0123456789abcdef","name":"Alice","level":9}]`,
	})
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), operatorReasonBadLevel) {
		t.Fatalf("越界 OP 等级应报告: %v", audit.Codes())
	}
}

func TestAuditServerOperatorsBadJSON(t *testing.T) {
	dir := baselineDir(t, map[string]string{"banned-players.json": `{broken`})
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), operatorReasonBadJSON) {
		t.Fatalf("坏 JSON 应告警不阻断: %v", audit.Describe())
	}
}

func TestAuditServerOperatorsMissingFiles(t *testing.T) {
	dir := baselineDir(t, nil)
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if len(audit.Findings) != 0 {
		t.Fatalf("名单缺失不应报告风险")
	}
}

func TestAuditServerOperatorsSymlink(t *testing.T) {
	dir := baselineDir(t, nil)
	outside := filepath.Join(t.TempDir(), "ops.json")
	if err := os.WriteFile(outside, []byte("[]"), 0o600); err != nil {
		t.Fatalf("写入外部文件失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ops.json")); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditServerOperators(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接名单应阻断: %v", audit.Describe())
	}
}
