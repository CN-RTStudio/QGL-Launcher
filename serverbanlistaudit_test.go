package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func writeBan(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestAuditServerBanListEmptyDir(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerBanList(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != banReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
}

func TestAuditServerBanListValid(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-players.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Griefer","expires":"forever","reason":"grief"}]`)
	writeBan(t, dir, "banned-ips.json", `[{"ip":"203.0.113.9","expires":"forever","reason":"scan"}]`)
	audit := AuditServerBanList(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != banReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
	if audit.Summary() != "files=2 findings=1 blocking=0 warnings=0" {
		t.Fatalf("summary mismatch: %s", audit.Summary())
	}
}

func TestAuditServerBanListInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-players.json", `[{"uuid":`)
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonInvalidJSON {
		t.Fatalf("expected invalid-json: %+v", audit.Findings)
	}
}

func TestAuditServerBanListSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real-ips.json")
	if err := os.WriteFile(target, []byte(`[]`), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "banned-ips.json")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonSymlink {
		t.Fatalf("expected symlink blocking: %+v", audit.Findings)
	}
}

func TestAuditServerBanListBadIP(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[{"ip":"999.1.2.3","expires":"forever"}]`)
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonBadIP {
		t.Fatalf("expected bad-ip: %+v", audit.Findings)
	}
}

func TestAuditServerBanListWildcard(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[{"ip":"*","expires":"forever"}]`)
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonWildcard {
		t.Fatalf("expected wildcard-ban: %+v", audit.Findings)
	}
}

func TestAuditServerBanListBroadCIDR(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[{"ip":"10.0.0.0/8","expires":"forever"}]`)
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonBroadCIDR {
		t.Fatalf("expected broad-cidr: %+v", audit.Findings)
	}
}
