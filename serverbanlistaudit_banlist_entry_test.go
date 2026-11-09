package main

import (
	"strings"
	"testing"
)

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
