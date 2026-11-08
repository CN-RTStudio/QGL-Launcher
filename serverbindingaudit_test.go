package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestAuditServerBindingBadBooleans(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=yes\nenforce-secure-profile=maybe\nprevent-proxy-connections=1\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsBindingReason(audit, bindingReasonBadBoolean) {
		t.Fatalf("bad booleans should be reported: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("bad booleans must not block: %s", audit.Describe())
	}
}

func TestAuditServerBindingStatusExposure(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nserver-ip=0.0.0.0\nenable-status=true\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsBindingReason(audit, bindingReasonStatusPublic) {
		t.Fatalf("status on wildcard should warn: %s", audit.Describe())
	}
}

func TestAuditServerBindingNumericLimits(t *testing.T) {
	dir := t.TempDir()
	writeBindingProperties(t, dir, "online-mode=true\nmax-players=0\nview-distance=99\nnetwork-compression-threshold=999999\n")
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	for _, want := range []string{bindingReasonBadPlayerCap, bindingReasonBadViewDist, bindingReasonBadCompress} {
		if !containsBindingReason(audit, want) {
			t.Fatalf("missing %s in %s", want, audit.Describe())
		}
	}
}

func TestAuditServerBindingSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(real, []byte("online-mode=true\n"), 0o600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	link := filepath.Join(dir, "server.properties")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerBinding(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !containsBindingReason(audit, bindingReasonSymlink) {
		t.Fatalf("symlink must block: %s", audit.Describe())
	}
}

func TestParseIntBounded(t *testing.T) {
	cases := []struct {
		value string
		min   int
		max   int
		want  int
		ok    bool
	}{
		{"20", 1, 100000, 20, true},
		{"0", 1, 100000, 0, false},
		{"-5", -10, 10, -5, true},
		{"12x", 1, 100, 0, false},
		{"", 1, 100, 0, false},
		{"999999999999", 1, 1 << 20, 0, false},
	}
	for _, c := range cases {
		got, ok := parseIntBounded(c.value, c.min, c.max)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("parseIntBounded(%q,%d,%d)=(%d,%v), want (%d,%v)", c.value, c.min, c.max, got, ok, c.want, c.ok)
		}
	}
}

func containsBindingReason(audit *ServerBindingAudit, reason string) bool {
	for _, code := range audit.Codes() {
		if code == reason {
			return true
		}
	}
	return false
}

func TestBindingDescribeStable(t *testing.T) {
	audit := &ServerBindingAudit{Findings: []BindingFinding{
		{Key: "online-mode", Value: "false", Reason: bindingReasonOfflineMode, Detail: "x", Blocking: true},
		{Reason: bindingReasonMissing, Detail: "y"},
	}}
	text := audit.Describe()
	if !strings.Contains(text, "offline-mode") || !strings.Contains(text, "missing") {
		t.Fatalf("describe lost codes: %s", text)
	}
	if len(audit.Codes()) != 2 {
		t.Fatalf("codes should dedupe/collect: %v", audit.Codes())
	}
}
