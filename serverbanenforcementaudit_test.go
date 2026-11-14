package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sbeWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestBanEnforcementClean(t *testing.T) {
	dir := t.TempDir()
	sbeWrite(t, dir, "banned-players.json", `[{"uuid":"1111","name":"griefer","reason":"破坏建筑"}]`)
	sbeWrite(t, dir, "banned-ips.json", `[]`)
	sbeWrite(t, dir, "ops.json", `[{"uuid":"2222","name":"admin"}]`)
	if a := AuditServerBanEnforcement(dir); a.HasWarnings() {
		t.Fatalf("封禁名单正常不应报警: %v", a.Describe())
	}
}

func TestBanEnforcementBadJSON(t *testing.T) {
	dir := t.TempDir()
	sbeWrite(t, dir, "banned-players.json", "[")
	a := AuditServerBanEnforcement(dir)
	if !a.Blocking() || !auditHasReason(a, sbeBadJSON) {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestBanEnforcementOpBanned(t *testing.T) {
	dir := t.TempDir()
	sbeWrite(t, dir, "banned-players.json", `[{"uuid":"2222","name":"admin","reason":"滥用权限"}]`)
	sbeWrite(t, dir, "ops.json", `[{"uuid":"2222","name":"admin"}]`)
	a := AuditServerBanEnforcement(dir)
	if !a.Blocking() || !auditHasReason(a, sbeOpBanned) {
		t.Fatalf("管理员被封应阻断: %v", a.Describe())
	}
}

func TestBanEnforcementNoUUID(t *testing.T) {
	dir := t.TempDir()
	sbeWrite(t, dir, "banned-players.json", `[{"name":"griefer","reason":"破坏"}]`)
	a := AuditServerBanEnforcement(dir)
	if !auditHasReason(a, sbeNoUUID) {
		t.Fatalf("缺 UUID 应提示: %v", a.Describe())
	}
}

func TestBanEnforcementWildcard(t *testing.T) {
	dir := t.TempDir()
	sbeWrite(t, dir, "banned-ips.json", `[{"ip":"10.*","reason":"网段"}]`)
	a := AuditServerBanEnforcement(dir)
	if !auditHasReason(a, sbeWildcard) {
		t.Fatalf("通配 IP 应提示: %v", a.Describe())
	}
}

func TestBanEnforcementNoReason(t *testing.T) {
	dir := t.TempDir()
	sbeWrite(t, dir, "banned-players.json", `[{"uuid":"1111","name":"griefer","reason":""}]`)
	a := AuditServerBanEnforcement(dir)
	if !auditHasReason(a, sbeNoReason) {
		t.Fatalf("缺原因应提示: %v", a.Describe())
	}
}
