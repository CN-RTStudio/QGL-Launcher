package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeWL(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestAuditServerWhitelistEmptyDir(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerWhitelist(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != wlReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("empty dir should be clean")
	}
}

func TestAuditServerWhitelistValid(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}]`)
	writeWL(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch","level":2,"bypassesPlayerLimit":false}]`)
	audit := AuditServerWhitelist(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != wlReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
	if audit.Summary() != "files=2 findings=1 blocking=0 warnings=0" {
		t.Fatalf("summary mismatch: %s", audit.Summary())
	}
}

func TestAuditServerWhitelistInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"uuid":`)
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wlReasonInvalidJSON {
		t.Fatalf("expected invalid-json blocking: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(`[]`), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "whitelist.json")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wlReasonSymlink {
		t.Fatalf("expected symlink blocking: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistBadUUID(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"uuid":"not-a-uuid","name":"Player"}]`)
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wlReasonBadUUID {
		t.Fatalf("expected bad-uuid: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistOfflineUUID(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"uuid":"3f4a1b2c-3d4e-3f60-8a9b-0c1d2e3f4a5b","name":"Player"}]`)
	audit := AuditServerWhitelist(dir)
	if audit.Blocking() {
		t.Fatalf("offline uuid must not block: %+v", audit.Findings)
	}
	if !audit.HasWarnings() || audit.Findings[0].Reason != wlReasonOfflineUUID {
		t.Fatalf("expected offline-uuid warning: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistDuplicateUUID(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[
{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Alpha"},
{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Beta"}]`)
	audit := AuditServerWhitelist(dir)
	codes := audit.Codes()
	if len(codes) != 1 || codes[0] != wlReasonDuplicateUUID {
		t.Fatalf("expected duplicate-uuid only: %v", codes)
	}
}

func TestAuditServerWhitelistBadName(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Bad Name"}]`)
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wlReasonBadName {
		t.Fatalf("expected bad-name blocking: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistBadOpLevel(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Root","level":9}]`)
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wlReasonBadOpLevel {
		t.Fatalf("expected bad-op-level: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistOpBypass(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "ops.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Root","level":4,"bypassesPlayerLimit":true}]`)
	audit := AuditServerWhitelist(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("bypass should warn only: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != wlReasonOpBypass {
		t.Fatalf("expected op-bypass: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistUUIDMismatch(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"Notch"}]`)
	writeWL(t, dir, "usercache.json", `[{"name":"Notch","uuid":"11111111-2222-4333-8444-555555555555","expiresOn":"2026-01-01"}]`)
	audit := AuditServerWhitelist(dir)
	seen := false
	for _, f := range audit.Findings {
		if f.Reason == wlReasonUUIDMismatch {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("expected uuid-mismatch: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistTooLarge(t *testing.T) {
	dir := t.TempDir()
	content := `[{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"` + strings.Repeat("a", wlMaxFileBytes) + `"}]`
	writeWL(t, dir, "whitelist.json", content)
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wlReasonTooLarge {
		t.Fatalf("expected too-large: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistEmpty(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[]`)
	audit := AuditServerWhitelist(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("empty whitelist should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != wlReasonEmptyWhitelist {
		t.Fatalf("expected empty-whitelist: %+v", audit.Findings)
	}
}

func TestAuditServerWhitelistBadShape(t *testing.T) {
	dir := t.TempDir()
	writeWL(t, dir, "whitelist.json", `[{"name":"NoUUID"}]`)
	audit := AuditServerWhitelist(dir)
	if !audit.Blocking() {
		t.Fatalf("missing uuid field must block: %+v", audit.Findings)
	}
	codes := audit.Codes()
	found := false
	for _, code := range codes {
		if code == wlReasonBadShape {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected bad-shape in codes: %v", codes)
	}
}

func TestWhitelistDescribeTruncates(t *testing.T) {
	dir := t.TempDir()
	entries := []string{}
	for i := 0; i < 10; i++ {
		entries = append(entries, `{"uuid":"not-a-uuid","name":"P"}`)
	}
	writeWL(t, dir, "whitelist.json", "["+strings.Join(entries, ",")+"]")
	audit := AuditServerWhitelist(dir)
	desc := audit.Describe()
	if !strings.Contains(desc, "等 11 项") {
		t.Fatalf("describe should truncate, got %s", desc)
	}
}
