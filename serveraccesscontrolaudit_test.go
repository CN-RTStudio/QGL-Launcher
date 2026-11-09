package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeACFile(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func acHasReason(audit AccessControlAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAccessControlMissingDirectoryBlocks(t *testing.T) {
	audit := AuditServerAccessControl(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() {
		t.Fatal("missing directory must block")
	}
	if !acHasReason(audit, acReasonMissing) {
		t.Fatal("missing reason not reported")
	}
}

func TestAccessControlCleanServerPasses(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "server.properties", "online-mode=true\nwhite-list=true\nenforce-whitelist=true\n")
	writeACFile(t, dir, "ops.json", `[{"uuid":"069a79f444e94726a5befca90e38aaf5","name":"Notch","level":3}]`)
	writeACFile(t, dir, "whitelist.json", `[{"uuid":"069a79f444e94726a5befca90e38aaf5","name":"Notch"}]`)
	audit := AuditServerAccessControl(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
	if len(audit.Sources) != 3 {
		t.Fatalf("expected three sources, got %v", audit.Sources)
	}
}

func TestAccessControlOfflineModeBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "server.properties", "online-mode=false\n")
	audit := AuditServerAccessControl(dir)
	if !audit.Blocking() {
		t.Fatal("offline mode must block")
	}
	if !acHasReason(audit, acReasonOfflineMode) {
		t.Fatal("offline-mode reason not reported")
	}
}

func TestAccessControlLevelFourOpBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "ops.json", `[{"uuid":"069a79f444e94726a5befca90e38aaf5","name":"admin","level":4}]`)
	audit := AuditServerAccessControl(dir)
	if !audit.Blocking() {
		t.Fatal("level 4 op must block")
	}
	if !acHasReason(audit, acReasonOpTooHigh) {
		t.Fatal("op-level reason not reported")
	}
}

func TestAccessControlDuplicateOpWarns(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "ops.json", `[
		{"uuid":"069a79f444e94726a5befca90e38aaf5","name":"Notch","level":2},
		{"uuid":"069a79f4-44e9-4726-a5be-fca90e38aaf5","name":"notch","level":2}
	]`)
	audit := AuditServerAccessControl(dir)
	if audit.Blocking() {
		t.Fatalf("duplicates must not block: %s", audit.Describe())
	}
	if !acHasReason(audit, acReasonDuplicateEntry) {
		t.Fatal("duplicate reason not reported")
	}
}

func TestAccessControlMalformedOpsBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "ops.json", `{"uuid":"x"}`)
	audit := AuditServerAccessControl(dir)
	if !audit.Blocking() {
		t.Fatal("malformed ops must block")
	}
	if !acHasReason(audit, acReasonMalformed) {
		t.Fatal("malformed reason not reported")
	}
}

func TestAccessControlMissingOpFieldBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "ops.json", `[{"uuid":"","name":""}]`)
	audit := AuditServerAccessControl(dir)
	if !acHasReason(audit, acReasonMissingField) {
		t.Fatal("missing field not reported")
	}
}

func TestAccessControlShortUUIDBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "ops.json", `[{"uuid":"abc","name":"x","level":1}]`)
	audit := AuditServerAccessControl(dir)
	if !acHasReason(audit, acReasonMalformed) {
		t.Fatal("short uuid not reported")
	}
}

func TestAccessControlWhitelistDisabledWarns(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "server.properties", "white-list=false\n")
	audit := AuditServerAccessControl(dir)
	if audit.Blocking() {
		t.Fatal("disabled whitelist must not block")
	}
	if !acHasReason(audit, acReasonWhitelistOff) {
		t.Fatal("whitelist reason not reported")
	}
}

func TestAccessControlWhitelistWithoutEnforceWarns(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "server.properties", "white-list=true\n")
	audit := AuditServerAccessControl(dir)
	if !acHasReason(audit, acReasonWhitelistOff) {
		t.Fatal("missing enforce-whitelist not reported")
	}
}

func TestAccessControlMalformedBanBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "banned-ips.json", `not-json`)
	audit := AuditServerAccessControl(dir)
	if !audit.Blocking() {
		t.Fatal("malformed ban list must block")
	}
}

func TestAccessControlWildcardBanWarns(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "banned-ips.json", `[{"ip":"10.*","reason":"grief"}]`)
	audit := AuditServerAccessControl(dir)
	if audit.Blocking() {
		t.Fatalf("wildcard ban must not block: %s", audit.Describe())
	}
	if !acHasReason(audit, acReasonMalformed) {
		t.Fatal("wildcard ban not reported")
	}
}

func TestAccessControlEmptyWhitelistEntryBlocks(t *testing.T) {
	dir := t.TempDir()
	writeACFile(t, dir, "whitelist.json", `[{"uuid":"069a79f444e94726a5befca90e38aaf5"}]`)
	audit := AuditServerAccessControl(dir)
	if !acHasReason(audit, acReasonMissingField) {
		t.Fatal("whitelist missing name not reported")
	}
}

func TestAccessControlOversizedOpsBlocks(t *testing.T) {
	dir := t.TempDir()
	body := "["
	for i := 0; i < acMaxEntries+8; i++ {
		if i > 0 {
			body += ","
		}
		body += `{"uuid":"069a79f444e94726a5befca90e38aaf5","name":"op","level":1}`
	}
	body += "]"
	writeACFile(t, dir, "ops.json", body)
	audit := AuditServerAccessControl(dir)
	if !acHasReason(audit, acReasonTooLarge) {
		t.Fatal("oversized ops not reported")
	}
}

func TestAccessControlDescribeSkipsOK(t *testing.T) {
	audit := AccessControlAudit{}
	audit.add("", acReasonOK, "fine", false)
	if audit.Describe() != "访问控制未发现风险" {
		t.Fatalf("unexpected describe: %s", audit.Describe())
	}
}
