package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestWhitelistRawShapeReasons(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte("{"), 0o644); err != nil {
		t.Fatalf("write broken: %v", err)
	}
	if ok, reason := wlLoadRawShape(broken); ok || reason != wlReasonInvalidJSON {
		t.Fatalf("非法 JSON 应返回 invalid-json: %v %q", ok, reason)
	}
	noUUID := filepath.Join(dir, "nouuid.json")
	if err := os.WriteFile(noUUID, []byte(`[{"name":"alice"}]`), 0o644); err != nil {
		t.Fatalf("write nouuid: %v", err)
	}
	if ok, reason := wlLoadRawShape(noUUID); ok || reason != wlReasonBadShape {
		t.Fatalf("缺 uuid 应返回 bad-shape: %v %q", ok, reason)
	}
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`[{"uuid":"u1"}]`), 0o644); err != nil {
		t.Fatalf("write good: %v", err)
	}
	if ok, reason := wlLoadRawShape(good); !ok || reason != "" {
		t.Fatalf("结构完整应通过: %v %q", ok, reason)
	}
	if ok, reason := wlLoadRawShape(filepath.Join(dir, "absent.json")); ok || reason != wlReasonUnreadable {
		t.Fatalf("读取失败应返回 unreadable: %v %q", ok, reason)
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
