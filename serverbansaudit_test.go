package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bxaWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func bxaHas(a *BanAudit, file, reason string) bool {
	for _, f := range a.Findings {
		if f.File == file && f.Reason == reason {
			return true
		}
	}
	return false
}

func TestBanAuditClean(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":"203.0.113.9","reason":"griefing","expires":"forever"}]`)
	bxaWrite(t, dir, bxaPlayerFile, `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Griefer","reason":"griefing","expires":"forever"}]`)
	a := AuditServerBans(dir)
	if a.HasWarnings() {
		t.Fatalf("干净名单不应报警: %v", a.Describe())
	}
}

func TestBanAuditMissingFiles(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaMiss) || !bxaHas(a, bxaPlayerFile, bxaMiss) {
		t.Fatalf("缺少两份名单应记录: %v", a.Describe())
	}
}

func TestBanAuditEmptyDir(t *testing.T) {
	a := AuditServerBans("")
	if !bxaHas(a, bxaIPFile, bxaMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestBanAuditInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaJSON) {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestBanAuditWildcardAddress(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":"0.0.0.0/0","reason":"lockdown","expires":"forever"}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaWildcard) {
		t.Fatalf("全地址封禁应阻断: %v", a.Describe())
	}
}

func TestBanAuditWildcardAll(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":"*","reason":"lockdown","expires":"forever"}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaWildcard) {
		t.Fatalf("通配封禁应阻断: %v", a.Describe())
	}
}

func TestBanAuditExpired(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":"203.0.113.9","reason":"temp","expires":"2020-01-02 03:04:05 +0000"}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaStale) {
		t.Fatalf("过期封禁应提示: %v", a.Describe())
	}
}

func TestBanAuditReasonControl(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaPlayerFile, `[{"uuid":"abc","reason":"bad\u001b[31m"}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaPlayerFile, bxaReasonCtl) {
		t.Fatalf("控制字符理由应阻断: %v", a.Describe())
	}
}

func TestBanAuditReasonLong(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaPlayerFile, `[{"uuid":"abc","reason":"`+strings.Repeat("x", 300)+`"}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaPlayerFile, bxaReasonLong) {
		t.Fatalf("超长理由应提示: %v", a.Describe())
	}
}

func TestBanAuditDuplicateTarget(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":"203.0.113.9"},{"ip":"203.0.113.9"}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaDupTarget) {
		t.Fatalf("重复目标应阻断: %v", a.Describe())
	}
}

func TestBanAuditEmptyEntry(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{}]`)
	a := AuditServerBans(dir)
	if !bxaHas(a, bxaIPFile, bxaShape) {
		t.Fatalf("空条目应阻断: %v", a.Describe())
	}
}

func TestBanAuditBOM(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, "\ufeff"+`[{"ip":"203.0.113.9","reason":"griefing","expires":"forever"}]`)
	bxaWrite(t, dir, bxaPlayerFile, "\ufeff[]")
	a := AuditServerBans(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 的合法名单不应报警: %v", a.Describe())
	}
}

func TestBanAuditDescribeMultiple(t *testing.T) {
	dir := t.TempDir()
	bxaWrite(t, dir, bxaIPFile, `[{"ip":"0.0.0.0/0","reason":"x"}]`)
	bxaWrite(t, dir, bxaPlayerFile, `[{}]`)
	a := AuditServerBans(dir)
	desc := a.Describe()
	if !strings.Contains(desc, bxaWildcard) || !strings.Contains(desc, bxaShape) {
		t.Fatalf("描述应包含两类原因: %s", desc)
	}
}
