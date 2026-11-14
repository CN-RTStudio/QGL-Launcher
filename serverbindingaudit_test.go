package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeBindingProperties(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o600); err != nil {
		t.Fatalf("write properties: %v", err)
	}
}

func TestAuditServerBindingClean(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nserver-ip=127.0.0.1\nenforce-secure-profile=true\nprevent-proxy-connections=true\nmax-players=20\nview-distance=10\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() {
		t.Fatalf("clean binding should not block: %s", audit.Describe())
	}
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != bindingReasonBindLoopback {
		t.Fatalf("expected loopback note only, got %s", audit.Describe())
	}
	if !audit.Present {
		t.Fatal("properties should be marked present")
	}
}

func TestAuditServerBindingMissing(t *testing.T) {
	dir := t.TempDir()
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Present || len(audit.Findings) != 1 || audit.Findings[0].Reason != bindingReasonMissing {
		t.Fatalf("expected missing finding, got %+v", audit)
	}
	if audit.Blocking() {
		t.Fatal("missing properties must not block")
	}
}

func TestAuditServerBindingOfflineModeBlocks(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=false\nserver-ip=127.0.0.1\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("offline mode must block: %s", audit.Describe())
	}
	if !containsBindingReason(audit, bindingReasonOfflineMode) {
		t.Fatalf("expected offline-mode code, got %v", audit.Codes())
	}
}

func TestAuditServerBindingBindAllWarns(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nserver-ip=\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() {
		t.Fatal("empty bind must only warn")
	}
	if !audit.HasWarnings() {
		t.Fatalf("empty server-ip should warn: %s", audit.Describe())
	}
}

func TestAuditServerBindingWildcardAndPublic(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nserver-ip=0.0.0.0\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsBindingReason(audit, bindingReasonBindAll) {
		t.Fatalf("wildcard should map to bind-all: %s", audit.Describe())
	}

	dir2 := t.TempDir()
	writeBindingProperties(t, dir2, "online-mode=true\nserver-ip=203.0.113.9\n")
	audit2, err := AuditServerBinding(dir2)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsBindingReason(audit2, bindingReasonBindPublic) {
		t.Fatalf("public address should be flagged: %s", audit2.Describe())
	}
}

func TestAuditServerBindingBadBindAddressBlocks(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nserver-ip=..\\evil\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsBindingReason(audit, bindingReasonBadBind) {
		t.Fatalf("path-like bind should be rejected: %s", audit.Describe())
	}
}

func TestAuditServerBindingSecureProfileOff(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nenforce-secure-profile=false\nprevent-proxy-connections=false\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsBindingReason(audit, bindingReasonSecureChat) {
		t.Fatalf("secure profile off should warn: %s", audit.Describe())
	}
	if !containsBindingReason(audit, bindingReasonProxyAllowed) {
		t.Fatalf("proxy connections allowed should warn: %s", audit.Describe())
	}
}
