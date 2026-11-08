package main

import (
	"os"
	"path/filepath"
	"testing"
)

func ppWrite(t *testing.T, dir, name, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", name, err)
	}
	return path
}

func ppHasReason(a PlayerPrivacyAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPlayerPrivacyClean(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "usercache.json", `[{"name":"Steve","uuid":"11111111-1111-1111-1111-111111111111","expiresOn":"2999-01-01 00:00:00 +0000"}]`, 0o600)
	ppWrite(t, dir, "banned-ips.json", `[{"ip":"10.0.0.1","reason":"x","expires":"forever"}]`, 0o600)
	ppWrite(t, dir, "ops.json", `[{"uuid":"11111111-1111-1111-1111-111111111111","name":"Steve","level":1,"bypassesPlayerLimit":false}]`, 0o600)
	ppWrite(t, dir, "server.properties", "online-mode=true\nserver-port=25565\n", 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("期望无风险，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacySymlinkUsercache(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(target, []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "usercache.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyWorldWritable(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "banned-ips.json", `[]`, 0o666)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("期望 world-writable 阻断，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyMalformedJSON(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "usercache.json", `{"name":"broken"}`, 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonMalformedJSON) {
		t.Fatalf("期望 malformed-json，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyDuplicateUUID(t *testing.T) {
	dir := t.TempDir()
	body := `[{"name":"A","uuid":"11111111-1111-1111-1111-111111111111","expiresOn":"2999-01-01 00:00:00 +0000"},
{"name":"B","uuid":"11111111-1111-1111-1111-111111111111","expiresOn":"2999-01-01 00:00:00 +0000"}]`
	ppWrite(t, dir, "usercache.json", body, 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonDuplicateUUID) {
		t.Fatalf("期望 duplicate-uuid，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyStaleEntry(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "usercache.json", `[{"name":"Steve","uuid":"11111111-1111-1111-1111-111111111111","expiresOn":"2001-01-01 00:00:00 +0000"}]`, 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonStaleEntry) {
		t.Fatalf("期望 stale-entry，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyInvalidOperatorUUID(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "ops.json", `[{"uuid":"not-a-uuid","name":"x","level":2}]`, 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonBadName) || !a.Blocking() {
		t.Fatalf("期望非法 UUID 阻断，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyFullOpLevel(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "ops.json", `[{"uuid":"11111111-1111-1111-1111-111111111111","name":"Steve","level":4,"bypassesPlayerLimit":true}]`, 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonOpLevel) || !ppHasReason(a, ppReasonBypassLimit) {
		t.Fatalf("期望 4 级与绕过人数上限告警，得到 %s", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("4 级权限不应阻断")
	}
}

func TestPlayerPrivacyBannedAllAndInvalidIP(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "banned-ips.json", `[{"ip":"*"},{"ip":"999.1.1.1"}]`, 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonBannedAll) || !ppHasReason(a, ppReasonInvalidIP) {
		t.Fatalf("期望 banned-all 与 invalid-ip，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyOfflineMode(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "server.properties", "online-mode=false\n", 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonOnlineMode) {
		t.Fatalf("期望 offline-mode，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyLogLeak(t *testing.T) {
	dir := t.TempDir()
	ppWrite(t, dir, "logs/latest.log", "[12:00:00] [Server thread/INFO]: Steve[/192.168.1.20:51234] logged in\n", 0o600)
	a := AuditServerPlayerPrivacy(dir)
	if !ppHasReason(a, ppReasonLogIPLeak) {
		t.Fatalf("期望 log-ip-leak，得到 %s", a.Describe())
	}
}

func TestPlayerPrivacyMissingDir(t *testing.T) {
	a := AuditServerPlayerPrivacy(filepath.Join(t.TempDir(), "absent"))
	if !a.Blocking() {
		t.Fatalf("期望目录缺失阻断，得到 %s", a.Describe())
	}
}
