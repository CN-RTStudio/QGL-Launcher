package main

import (
	"os"
	"path/filepath"
	"testing"
)

func syoWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ops.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write ops: %v", err)
	}
}

const (
	syoOnlineSample  = "069a79f444e94726a5befca90e38aaf5"
	syoSecondSample  = "61699b2ed3274a019f1e0ea8c3f06bc6"
	syoOfflineSample = "53e2f5e1-3c3c-3000-8000-000000000000"
)

func TestOpsClean(t *testing.T) {
	dir := t.TempDir()
	syoWrite(t, dir, `[{"uuid":"`+syoOnlineSample+`","name":"admin","level":4,"bypassesPlayerLimit":false}]`)
	a := AuditServerOpsPrivilege(dir)
	if a.HasWarnings() {
		t.Fatalf("合规运维配置不应报警: %v", a.Describe())
	}
	if a.Entries != 1 {
		t.Fatalf("应解析出 1 个运维账号: %d", a.Entries)
	}
}

func TestOpsMissing(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoMissing) {
		t.Fatalf("缺少 ops.json 应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("缺少文件不应阻断: %v", a.Describe())
	}
}

func TestOpsOverLevel(t *testing.T) {
	dir := t.TempDir()
	syoWrite(t, dir, `[{"uuid":"`+syoOnlineSample+`","name":"admin","level":9}]`)
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoOverLevel) || !a.Blocking() {
		t.Fatalf("越权等级应阻断: %v", a.Describe())
	}
}

func TestOpsDuplicate(t *testing.T) {
	dir := t.TempDir()
	syoWrite(t, dir, `[{"uuid":"`+syoOnlineSample+`","name":"a","level":3},{"uuid":"`+syoOnlineSample+`","name":"b","level":2}]`)
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoDuplicate) || !a.Blocking() {
		t.Fatalf("重复 UUID 应阻断: %v", a.Describe())
	}
}

func TestOpsOfflineUUID(t *testing.T) {
	dir := t.TempDir()
	syoWrite(t, dir, `[{"uuid":"`+syoOfflineSample+`","name":"a","level":2}]`)
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoOfflineUUID) || !a.Blocking() {
		t.Fatalf("离线 UUID 应阻断: %v", a.Describe())
	}
}

func TestOpsBadJSON(t *testing.T) {
	dir := t.TempDir()
	syoWrite(t, dir, `[{"uuid":`)
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoBadJSON) || !a.Blocking() {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestOpsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-ops.json")
	if err := os.WriteFile(target, []byte(`[]`), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "ops.json")); err != nil {
		t.Skipf("平台不支持创建符号链接: %v", err)
	}
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoSymlink) || !a.Blocking() {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}

func TestOpsTooMany(t *testing.T) {
	dir := t.TempDir()
	buf := make([]byte, 0, 4096)
	buf = append(buf, '[')
	for i := 0; i < syoMaxOps+1; i++ {
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, []byte(`{"uuid":"069a79f444e94726a5befca90e38aa`+syoPad(i)+`","name":"x","level":2}`)...)
	}
	buf = append(buf, ']')
	syoWrite(t, dir, string(buf))
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoTooMany) {
		t.Fatalf("超量运维账号应告警: %v", a.Describe())
	}
}

func syoPad(value int) string {
	table := []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20"}
	if value >= 0 && value < len(table) {
		return table[value]
	}
	return "ff"
}

func TestOpsByPassWarning(t *testing.T) {
	dir := t.TempDir()
	syoWrite(t, dir, `[{"uuid":"`+syoSecondSample+`","name":"helper","level":2,"bypassesPlayerLimit":true}]`)
	a := AuditServerOpsPrivilege(dir)
	if !auditHasReason(a, syoBypass) {
		t.Fatalf("绕过满员限制应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("绕过满员限制不应阻断: %v", a.Describe())
	}
}
