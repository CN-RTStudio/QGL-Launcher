package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func opxWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ops.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func opxHas(a *OpSecurityAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const opxValidUUID = "069a79f4-44e9-4726-a5be-fca90e38aaf5"

func TestOpSecurityClean(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"`+opxValidUUID+`","name":"Alice","level":3,"bypassesPlayerLimit":false}]`)
	a := AuditServerOpSecurity(dir)
	if a.HasWarnings() {
		t.Fatalf("干净名单不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净名单不应阻断: %v", a.Describe())
	}
}

func TestOpSecurityMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxMiss) {
		t.Fatalf("缺少 ops.json 应记录: %v", a.Describe())
	}
}

func TestOpSecurityEmptyDir(t *testing.T) {
	a := AuditServerOpSecurity("")
	if !opxHas(a, opxMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestOpSecurityInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxJSON) {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestOpSecurityInvalidUUID(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"not-a-uuid","name":"Alice","level":2}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxUUID) {
		t.Fatalf("非法 uuid 应阻断: %v", a.Describe())
	}
}

func TestOpSecurityDuplicateUUID(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"`+opxValidUUID+`","name":"Alice","level":2},`+
		`{"uuid":"`+strings.ToUpper(opxValidUUID)+`","name":"Bob","level":2}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxUUIDDup) {
		t.Fatalf("重复 uuid 应阻断: %v", a.Describe())
	}
}

func TestOpSecurityEmptyName(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"`+opxValidUUID+`","name":"  ","level":2}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxNameEmpty) {
		t.Fatalf("空玩家名应阻断: %v", a.Describe())
	}
}

func TestOpSecurityLevelZero(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"`+opxValidUUID+`","name":"Alice","level":0}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxLevelRange) {
		t.Fatalf("等级越界应阻断: %v", a.Describe())
	}
}

func TestOpSecurityLevelFour(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"`+opxValidUUID+`","name":"Alice","level":4}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxLevelTop) {
		t.Fatalf("4 级权限应提示: %v", a.Describe())
	}
}

func TestOpSecurityBypass(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"`+opxValidUUID+`","name":"Alice","level":2,"bypassesPlayerLimit":true}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxBypass) {
		t.Fatalf("无视人数上限应提示: %v", a.Describe())
	}
}

func TestOpSecurityTooMany(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("[")
	for i := 0; i < 10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"uuid":"` + opxValidUUID + `","name":"Alice","level":2}`)
	}
	b.WriteString("]")
	opxWrite(t, dir, b.String())
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxTooMany) {
		t.Fatalf("超量 OP 应提示: %v", a.Describe())
	}
}

func TestOpSecurityEmptyEntry(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{}]`)
	a := AuditServerOpSecurity(dir)
	if !opxHas(a, opxShape) {
		t.Fatalf("空条目应阻断: %v", a.Describe())
	}
}

func TestOpSecurityBOM(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, "\ufeff"+`[{"uuid":"`+opxValidUUID+`","name":"Alice","level":2}]`)
	a := AuditServerOpSecurity(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 的合法名单不应报警: %v", a.Describe())
	}
}

func TestOpSecurityDescribeSorts(t *testing.T) {
	dir := t.TempDir()
	opxWrite(t, dir, `[{"uuid":"bad","name":"Alice","level":4}]`)
	a := AuditServerOpSecurity(dir)
	desc := a.Describe()
	if !strings.Contains(desc, opxUUID) || !strings.Contains(desc, opxLevelTop) {
		t.Fatalf("描述应包含原因键: %s", desc)
	}
}
