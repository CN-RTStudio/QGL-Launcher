package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
