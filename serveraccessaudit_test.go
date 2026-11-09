package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeAccessFixture(t *testing.T, dir, name string, value interface{}) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}

func TestAuditServerAccessClean(t *testing.T) {
	dir := t.TempDir()
	writeAccessFixture(t, dir, "ops.json", []map[string]interface{}{
		{"uuid": "11111111111111111111111111111111", "name": "Alice", "level": 2},
	})
	writeAccessFixture(t, dir, "whitelist.json", []map[string]interface{}{
		{"uuid": "22222222-2222-2222-2222-222222222222", "name": "Bob"},
	})
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() {
		t.Fatalf("clean fixture should not block: %s", audit.Describe())
	}
	if len(audit.Findings) != 0 {
		t.Fatalf("expected no findings: %s", audit.Describe())
	}
	if len(audit.Files) != len(accessFileNames) {
		t.Fatalf("expected %d file audits, got %d", len(accessFileNames), len(audit.Files))
	}
}

func TestAuditServerAccessMalformedBlocks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ops.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("malformed ops.json must block")
	}
	if audit.Codes()[0] != accessReasonMalformed {
		t.Fatalf("expected malformed code, got %v", audit.Codes())
	}
}

func TestAuditServerAccessSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("[]"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "whitelist.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("symlinked whitelist must block")
	}
	for _, file := range audit.Files {
		if file.Name == "whitelist.json" && !file.Symlink {
			t.Fatalf("expected symlink flag on whitelist.json")
		}
	}
}

func TestAuditServerAccessDuplicateUUID(t *testing.T) {
	dir := t.TempDir()
	writeAccessFixture(t, dir, "ops.json", []map[string]interface{}{
		{"uuid": "33333333333333333333333333333333", "name": "Alice", "level": 1},
		{"uuid": "33333333-3333-3333-3333-333333333333", "name": "Alicia", "level": 3},
	})
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("duplicate uuid must block: %s", audit.Describe())
	}
	found := false
	for _, finding := range audit.Findings {
		if finding.Reason == accessReasonDuplicate {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected duplicate finding, got %s", audit.Describe())
	}
}

func TestAuditServerAccessOpsLevelRange(t *testing.T) {
	dir := t.TempDir()
	writeAccessFixture(t, dir, "ops.json", []map[string]interface{}{
		{"uuid": "44444444444444444444444444444444", "name": "Alice", "level": 9},
	})
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("out-of-range op level must block: %s", audit.Describe())
	}
	dir = t.TempDir()
	writeAccessFixture(t, dir, "ops.json", []map[string]interface{}{
		{"uuid": "55555555555555555555555555555555", "name": "Alice", "level": 4},
	})
	audit, err = AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("level 4 must warn without blocking: %s", audit.Describe())
	}
}

func TestAuditServerAccessBannedIP(t *testing.T) {
	dir := t.TempDir()
	writeAccessFixture(t, dir, "banned-ips.json", []map[string]interface{}{
		{"ip": "0.0.0.0", "reason": "all"},
	})
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("wildcard ban must block: %s", audit.Describe())
	}
	dir = t.TempDir()
	writeAccessFixture(t, dir, "banned-ips.json", []map[string]interface{}{
		{"ip": "203.0.113.9", "reason": "grief"},
	})
	audit, err = AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() {
		t.Fatalf("normal ban must not block: %s", audit.Describe())
	}
	dir = t.TempDir()
	writeAccessFixture(t, dir, "banned-ips.json", []map[string]interface{}{
		{"ip": "not-an-ip"},
	})
	audit, err = AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("invalid ip must block")
	}
}

func TestAuditServerAccessWhitelistNameRequired(t *testing.T) {
	dir := t.TempDir()
	writeAccessFixture(t, dir, "whitelist.json", []map[string]interface{}{
		{"uuid": "66666666666666666666666666666666"},
	})
	audit, err := AuditServerAccess(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("missing whitelist name must block: %s", audit.Describe())
	}
}
