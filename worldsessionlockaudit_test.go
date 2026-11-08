package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeWSL(t *testing.T, dir, rel string, body []byte, mode os.FileMode, age time.Duration) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
}

func levelDatBody() []byte {
	body := make([]byte, 128)
	body[0] = 0x1f
	body[1] = 0x8b
	body[2] = 0x08
	return body
}

func TestAuditServerSessionLocksMissing(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerSessionLocks(dir)
	if audit.Blocking() {
		t.Fatalf("missing worlds are informational: %+v", audit.Findings)
	}
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != wslReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksHealthy(t *testing.T) {
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), levelDatBody(), 0o644, time.Hour)
	writeWSL(t, dir, filepath.Join("world", "session.lock"), []byte("lock"), 0o644, 2*time.Hour)
	audit := auditServerSessionLocksAt(dir, time.Now())
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("healthy world should pass: %+v", audit.Findings)
	}
	if len(audit.Worlds) != 1 {
		t.Fatalf("expected one world: %v", audit.Worlds)
	}
}

func TestAuditServerSessionLocksInUse(t *testing.T) {
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), levelDatBody(), 0o644, time.Hour)
	writeWSL(t, dir, filepath.Join("world", "session.lock"), []byte("lock"), 0o644, 0)
	audit := auditServerSessionLocksAt(dir, time.Now())
	if !audit.Blocking() || audit.Findings[0].Reason != wslReasonWorldInUse {
		t.Fatalf("fresh lock must block: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksStale(t *testing.T) {
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), levelDatBody(), 0o644, time.Hour)
	writeWSL(t, dir, filepath.Join("world", "session.lock"), []byte("lock"), 0o644, 200*24*time.Hour)
	audit := auditServerSessionLocksAt(dir, time.Now())
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("stale lock should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != wslReasonLockStale {
		t.Fatalf("expected lock-stale: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksMissingLock(t *testing.T) {
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), levelDatBody(), 0o644, time.Hour)
	audit := auditServerSessionLocksAt(dir, time.Now())
	if audit.Findings[0].Reason != wslReasonMissingLock {
		t.Fatalf("expected missing-lock: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksBadLevelDat(t *testing.T) {
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), make([]byte, 64), 0o644, time.Hour)
	audit := auditServerSessionLocksAt(dir, time.Now())
	if !audit.Blocking() || audit.Findings[0].Reason != wslReasonBadLevelDat {
		t.Fatalf("expected bad-level-dat: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksSymlinkWorld(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "real-world")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "world")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerSessionLocks(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wslReasonSymlink {
		t.Fatalf("expected symlink block: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksNotDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "world"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit := AuditServerSessionLocks(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != wslReasonNotDirectory {
		t.Fatalf("expected not-directory: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("unix permission bits not meaningful on windows")
	}
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), levelDatBody(), 0o644, time.Hour)
	writeWSL(t, dir, filepath.Join("world", "session.lock"), []byte("lock"), 0o644, 2*time.Hour)
	if err := os.Chmod(filepath.Join(dir, "world"), 0o777); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	audit := auditServerSessionLocksAt(dir, time.Now())
	found := false
	for _, f := range audit.Findings {
		if f.Reason == wslReasonWorldReadable {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected world-readable: %+v", audit.Findings)
	}
}

func TestAuditServerSessionLocksDescribeSummary(t *testing.T) {
	dir := t.TempDir()
	writeWSL(t, dir, filepath.Join("world", "level.dat"), levelDatBody(), 0o644, time.Hour)
	writeWSL(t, dir, filepath.Join("world", "session.lock"), []byte("lock"), 0o644, 0)
	audit := auditServerSessionLocksAt(dir, time.Now())
	if audit.Describe() == "" || audit.Summary() == "" {
		t.Fatalf("describe/summary empty")
	}
	codes := audit.Codes()
	if len(codes) != 1 || codes[0] != wslReasonWorldInUse {
		t.Fatalf("unexpected codes: %v", codes)
	}
}
