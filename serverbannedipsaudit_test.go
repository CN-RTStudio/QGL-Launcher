package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)


func sbiHas(findings []BannedIPFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const sbiGood = `[{"ip":"203.0.113.9","created":"2026-01-01 00:00:00 +0800","source":"Server","expires":"forever"}]`

func TestBannedIPsMissingFile(t *testing.T) {
	a := AuditServerBannedIPs(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少封禁清单不应报警: %v", a.Describe())
	}
}

func TestBannedIPsClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "banned-ips.json", sbiGood)
	a := AuditServerBannedIPs(dir)
	if a.HasWarnings() {
		t.Fatalf("不应有发现: %v", a.Describe())
	}
}

func TestBannedIPsBadJSON(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "banned-ips.json", "[{")
	a := AuditServerBannedIPs(dir)
	if !sbiHas(a.Findings, sbiReasonParse) || !a.Blocking() {
		t.Fatalf("期望解析失败阻断: %v", a.Describe())
	}
}

func TestBannedIPsInvalidAddress(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "banned-ips.json", `[{"ip":"../../etc/passwd","created":"x","source":"s","expires":"f"}]`)
	a := AuditServerBannedIPs(dir)
	if !sbiHas(a.Findings, sbiReasonAddress) || !a.Blocking() {
		t.Fatalf("期望地址非法阻断: %v", a.Describe())
	}
}

func TestBannedIPsDuplicate(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "banned-ips.json", `[{"ip":"203.0.113.9","created":"x","source":"s","expires":"f"},{"ip":"203.0.113.9","created":"x","source":"s","expires":"f"},{"ip":"203.0.113.9","created":"x","source":"s","expires":"f"}]`)
	a := AuditServerBannedIPs(dir)
	if !sbiHas(a.Findings, sbiReasonDup) {
		t.Fatalf("期望重复地址告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("重复地址不应阻断")
	}
}

func TestBannedIPsMissingTime(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "banned-ips.json", `[{"ip":"203.0.113.9","source":"s"}]`)
	a := AuditServerBannedIPs(dir)
	if !sbiHas(a.Findings, sbiReasonExpiry) {
		t.Fatalf("期望时间告警: %v", a.Describe())
	}
}

func TestBannedIPsTooLarge(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "banned-ips.json", strings.Repeat("x", sbiMaxFile+16))
	a := AuditServerBannedIPs(dir)
	if !sbiHas(a.Findings, sbiReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望超大阻断: %v", a.Describe())
	}
}

func TestBannedIPsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(sbiGood), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "banned-ips.json")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerBannedIPs(dir)
	if !sbiHas(a.Findings, sbiReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望符号链接阻断: %v", a.Describe())
	}
}
