package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func soaWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func soaHas(findings []OpsJsonFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestOperatorMissingFile(t *testing.T) {
	a := AuditServerOpsJson(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少 ops.json 不应报警: %v", a.Describe())
	}
}

func TestOperatorClean(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch","level":2,"bypassesPlayerLimit":false}]`)
	a := AuditServerOpsJson(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合法清单不应报警: %v", a.Describe())
	}
}

func TestOperatorInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `{"uuid":"x"}`)
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonShape) {
		t.Fatalf("非数组应阻断: %v", a.Describe())
	}
}

func TestOperatorBadUUID(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[{"uuid":"../../etc","name":"Bad","level":1,"bypassesPlayerLimit":false}]`)
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonUUID) {
		t.Fatalf("非法 uuid 应阻断: %v", a.Describe())
	}
}

func TestOperatorBadName(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"bad name!","level":1,"bypassesPlayerLimit":false}]`)
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonName) {
		t.Fatalf("非法玩家名应阻断: %v", a.Describe())
	}
}

func TestOperatorLevelOutOfRange(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch","level":9,"bypassesPlayerLimit":false}]`)
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonLevel) {
		t.Fatalf("越权 level 应阻断: %v", a.Describe())
	}
}

func TestOperatorMissingLevel(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}]`)
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonLevel) {
		t.Fatalf("缺 level 应阻断: %v", a.Describe())
	}
}

func TestOperatorDuplicate(t *testing.T) {
	dir := t.TempDir()
	dup := `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch","level":1,"bypassesPlayerLimit":false},` +
		`{"uuid":"069a79f444e94726a5befca90e38aaf5","name":"notch","level":1,"bypassesPlayerLimit":false}]`
	soaWriteFile(t, dir, "ops.json", dup)
	a := AuditServerOpsJson(dir)
	if a.Blocking() || !soaHas(a.Findings, soaReasonDup) {
		t.Fatalf("重复条目应告警: %v", a.Describe())
	}
}

func TestOperatorOwnerLevel(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch","level":4,"bypassesPlayerLimit":true}]`)
	a := AuditServerOpsJson(dir)
	if a.Blocking() || !soaHas(a.Findings, soaReasonOwner) {
		t.Fatalf("四级操作员应告警: %v", a.Describe())
	}
}

func TestOperatorTooMany(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 70; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Op%d","level":1,"bypassesPlayerLimit":false}`)
		b.WriteString("")
	}
	b.WriteString("]")
	raw := strings.ReplaceAll(strings.Repeat("", 0)+b.String(), "Op%d", "Op")
	soaWriteFile(t, dir, "ops.json", raw)
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonLargeN) {
		t.Fatalf("操作员数量超限应阻断: %v", a.Describe())
	}
}

func TestOperatorEmptyArray(t *testing.T) {
	dir := t.TempDir()
	soaWriteFile(t, dir, "ops.json", `[]`)
	a := AuditServerOpsJson(dir)
	if a.Blocking() || !soaHas(a.Findings, soaReasonEmpty) {
		t.Fatalf("空数组应告警: %v", a.Describe())
	}
}

func TestOperatorSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	soaWriteFile(t, dir, "real.json", `[]`)
	link := filepath.Join(dir, "ops.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerOpsJson(dir)
	if !a.Blocking() || !soaHas(a.Findings, soaReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
