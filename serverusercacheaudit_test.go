package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sucWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sucHas(findings []UserCacheFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const sucGood = `[{"name":"Steve","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","expiresOn":"2026-12-01 00:00:00 +0800"}]`

func TestUserCacheMissingFile(t *testing.T) {
	a := AuditServerUserCache(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少缓存文件不应报警: %v", a.Describe())
	}
}

func TestUserCacheClean(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", sucGood)
	a := AuditServerUserCache(dir)
	if a.HasWarnings() {
		t.Fatalf("不应有发现: %v", a.Describe())
	}
}

func TestUserCacheBadJSON(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", "{not json")
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonParse) || !a.Blocking() {
		t.Fatalf("期望解析失败阻断: %v", a.Describe())
	}
}

func TestUserCacheEmptyFile(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", "  \n")
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonParse) || !a.Blocking() {
		t.Fatalf("期望空文件阻断: %v", a.Describe())
	}
}

func TestUserCacheBadUUID(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", `[{"name":"Alex","uuid":"../../etc","expiresOn":"x"}]`)
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonUUID) || !a.Blocking() {
		t.Fatalf("期望 UUID 非法阻断: %v", a.Describe())
	}
}

func TestUserCacheBadName(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", `[{"name":"../evil","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","expiresOn":"x"}]`)
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonName) || !a.Blocking() {
		t.Fatalf("期望名称非法阻断: %v", a.Describe())
	}
}

func TestUserCacheDuplicateUUID(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", `[{"name":"Steve","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","expiresOn":"x"},{"name":"Alex","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","expiresOn":"x"}]`)
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonDup) {
		t.Fatalf("期望重复 UUID 告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("重复 UUID 不应阻断")
	}
}

func TestUserCacheExpiryMissing(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", `[{"name":"Steve","uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5"}]`)
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonExpiry) {
		t.Fatalf("期望过期时间告警: %v", a.Describe())
	}
}

func TestUserCacheTooLarge(t *testing.T) {
	dir := t.TempDir()
	sucWriteFile(t, dir, "usercache.json", strings.Repeat("x", sucMaxFile+16))
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望超大阻断: %v", a.Describe())
	}
}

func TestUserCacheSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(sucGood), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "usercache.json")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerUserCache(dir)
	if !sucHas(a.Findings, sucReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望符号链接阻断: %v", a.Describe())
	}
}
