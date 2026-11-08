package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCache(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, playerCacheFileName), []byte(body), 0o600); err != nil {
		t.Fatalf("写入缓存失败: %v", err)
	}
}

func TestAuditPlayerCacheClean(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, `[{"name":"Alice","uuid":"0123456789abcdef0123456789abcdef","expiresOn":"2099-01-01T00:00:00+08:00"}]`)
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || len(audit.Findings) != 0 || audit.Entries != 1 {
		t.Fatalf("干净缓存不应有问题: %s", audit.Describe())
	}
}

func TestAuditPlayerCacheBadUUID(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, `[{"name":"Alice","uuid":"zzz","expiresOn":"2099-01-01T00:00:00Z"}]`)
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), playerCacheReasonBadUUID) {
		t.Fatalf("非法 uuid 应报告: %v", audit.Codes())
	}
}

func TestAuditPlayerCacheDuplicate(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, `[
		{"name":"Alice","uuid":"0123456789abcdef0123456789abcdef"},
		{"name":"Alice2","uuid":"0123456789abcdef0123456789abcdef"}
	]`)
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), playerCacheReasonDuplicate) {
		t.Fatalf("重复 uuid 应报告: %v", audit.Codes())
	}
}

func TestAuditPlayerCacheBadName(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, `[{"name":"bad name!","uuid":"0123456789abcdef0123456789abcdef"}]`)
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), playerCacheReasonBadName) {
		t.Fatalf("非法玩家名应报告: %v", audit.Codes())
	}
}

func TestAuditPlayerCacheBadJSON(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, `{oops`)
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), playerCacheReasonBadJSON) {
		t.Fatalf("坏 JSON 应告警不阻断: %s", audit.Describe())
	}
}

func TestAuditPlayerCacheSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), playerCacheFileName)
	if err := os.WriteFile(outside, []byte("[]"), 0o600); err != nil {
		t.Fatalf("写入外部缓存失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, playerCacheFileName)); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接缓存应阻断: %s", audit.Describe())
	}
}

func TestAuditPlayerCacheMissing(t *testing.T) {
	audit, err := AuditPlayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Present || audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("缺失缓存应按空处理")
	}
}

func TestAuditPlayerCacheExpiredCounted(t *testing.T) {
	dir := t.TempDir()
	writeCache(t, dir, `[{"name":"Alice","uuid":"0123456789abcdef0123456789abcdef","expiresOn":"2000-01-01T00:00:00Z"}]`)
	audit, err := AuditPlayerCache(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Expired != 1 {
		t.Fatalf("过期条目应计数")
	}
}
