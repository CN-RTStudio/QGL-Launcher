package main

import (
	"os"
	"path/filepath"
	"testing"
)


func sqbReasons(a *QueryBindingAudit) map[string]bool {
	out := map[string]bool{}
	for _, f := range a.Findings {
		out[f.Reason] = true
	}
	return out
}

func TestAuditServerQueryBindingMissingDir(t *testing.T) {
	a := AuditServerQueryBinding(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonMissing] {
		t.Fatalf("expected missing: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingCleanDefaults(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=false\nserver-ip=\nenable-status=true\n")
	a := AuditServerQueryBinding(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingQueryEnabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=true\nquery.port=25565\n")
	a := AuditServerQueryBinding(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonQueryOn] {
		t.Fatalf("expected query finding: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonBindAll] {
		t.Fatalf("expected bind-all finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingPrivilegedPort(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=true\nquery.port=80\n")
	a := AuditServerQueryBinding(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonPortLow] {
		t.Fatalf("expected privileged port finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingZeroPort(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=true\nquery.port=0\n")
	a := AuditServerQueryBinding(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonPortZero] {
		t.Fatalf("expected zero port finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingOrphanPort(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=false\nquery.port=25566\n")
	a := AuditServerQueryBinding(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonOrphan] {
		t.Fatalf("expected orphan finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingInvalidPort(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "query.port=abc\n")
	a := AuditServerQueryBinding(dir)
	if a.Blocking() {
		t.Fatalf("unexpected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonBadValue] {
		t.Fatalf("expected bad-value: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingRconCollision(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=true\nquery.port=25575\nrcon.port=25575\n")
	a := AuditServerQueryBinding(dir)
	if !sqbReasons(a)[sqbReasonCollide] {
		t.Fatalf("expected collision finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingHostPath(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "server-ip=../../etc\n")
	a := AuditServerQueryBinding(dir)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
	if !sqbReasons(a)[sqbReasonHostPath] {
		t.Fatalf("expected host finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingWildcardHost(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=true\nserver-ip=0.0.0.0\n")
	a := AuditServerQueryBinding(dir)
	if !sqbReasons(a)[sqbReasonBindAll] {
		t.Fatalf("expected bind-all finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingStatusDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-status=false\n")
	a := AuditServerQueryBinding(dir)
	if !sqbReasons(a)[sqbReasonStatus] {
		t.Fatalf("expected status finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingBukkitQueryPlugins(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "server.properties", "enable-query=false\n")
	auditWriteFileAtRoot(t, dir, "bukkit.yml", "settings:\n  query-plugins: true\n  connection-throttle: 4000\n")
	a := AuditServerQueryBinding(dir)
	if !sqbReasons(a)[sqbReasonQueryOn] {
		t.Fatalf("expected bukkit query finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingBukkitNegativeThrottle(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileAtRoot(t, dir, "bukkit.yml", "settings:\n  connection-throttle: -1\n")
	a := AuditServerQueryBinding(dir)
	if !sqbReasons(a)[sqbReasonBadValue] {
		t.Fatalf("expected throttle finding: %s", a.Describe())
	}
}

func TestAuditServerQueryBindingSymlinkRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerQueryBinding(link)
	if !a.Blocking() {
		t.Fatalf("expected blocking: %s", a.Describe())
	}
}
