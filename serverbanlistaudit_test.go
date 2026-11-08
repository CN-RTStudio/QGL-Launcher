package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestAuditServerBanListNarrowCIDRPasses(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[{"ip":"10.1.2.0/24","expires":"forever"}]`)
	audit := AuditServerBanList(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("narrow cidr should be clean: %+v", audit.Findings)
	}
}

func TestAuditServerBanListStale(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-players.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Old","expires":"2020-01-01 00:00:00 +0000"}]`)
	audit := AuditServerBanList(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("stale ban should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != banReasonStale {
		t.Fatalf("expected stale-ban: %+v", audit.Findings)
	}
}

func TestAuditServerBanListBadExpiry(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[{"ip":"203.0.113.9","expires":"next-week"}]`)
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonBadExpiry {
		t.Fatalf("expected bad-expiry: %+v", audit.Findings)
	}
}

func TestAuditServerBanListBadUUIDAndName(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-players.json", `[{"uuid":"bad","name":"Player"}]`)
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonBadUUID {
		t.Fatalf("expected bad-uuid: %+v", audit.Findings)
	}
}

func TestAuditServerBanListDuplicate(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[
{"ip":"203.0.113.9","expires":"forever"},
{"ip":"203.0.113.9","expires":"forever"}]`)
	audit := AuditServerBanList(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("duplicate should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != banReasonDuplicate {
		t.Fatalf("expected duplicate-entry: %+v", audit.Findings)
	}
}

func TestAuditServerBanListTooLarge(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", "["+strings.Repeat(" ", banMaxFileBytes)+"]")
	audit := AuditServerBanList(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != banReasonTooLarge {
		t.Fatalf("expected too-large: %+v", audit.Findings)
	}
}

func TestAuditServerBanListBadReason(t *testing.T) {
	dir := t.TempDir()
	writeBan(t, dir, "banned-ips.json", `[{"ip":"203.0.113.9","expires":"forever","reason":"evil\u0007reason"}]`)
	audit := AuditServerBanList(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("control chars should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != banReasonBadReason {
		t.Fatalf("expected bad-reason: %+v", audit.Findings)
	}
}

func TestBanListDescribeTruncates(t *testing.T) {
	dir := t.TempDir()
	entries := []string{}
	for i := 0; i < 10; i++ {
		entries = append(entries, `{"ip":"bad","expires":"forever"}`)
	}
	writeBan(t, dir, "banned-ips.json", "["+strings.Join(entries, ",")+"]")
	audit := AuditServerBanList(dir)
	if !strings.Contains(audit.Describe(), "等 10 项") {
		t.Fatalf("describe should truncate: %s", audit.Describe())
	}
}
