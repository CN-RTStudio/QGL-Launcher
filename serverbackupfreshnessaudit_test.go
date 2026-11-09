package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeBK(t *testing.T, dir, rel string, size int, mode os.FileMode, age time.Duration) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, make([]byte, size), mode); err != nil {
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

func TestAuditServerBackupsMissing(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerBackups(dir)
	if audit.Blocking() {
		t.Fatalf("missing backups dir is informational: %+v", audit.Findings)
	}
	if len(audit.Findings) != 2 {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsFresh(t *testing.T) {
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "world-20260101.zip"), 64<<10, 0o644, time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("fresh backup should be clean: %+v", audit.Findings)
	}
	if len(audit.Backups) != 1 {
		t.Fatalf("expected one backup: %+v", audit.Backups)
	}
}

func TestAuditServerBackupsStale(t *testing.T) {
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "old.zip"), 64<<10, 0o644, 30*24*time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("stale backup should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != bkReasonStaleBackup {
		t.Fatalf("expected stale-backup: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsEmpty(t *testing.T) {
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "tiny.zip"), 100, 0o644, time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	if audit.Findings[0].Reason != bkReasonEmptyBackup {
		t.Fatalf("expected empty-backup: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsWorldWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("unix permission bits not meaningful on windows")
	}
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "open.zip"), 64<<10, 0o666, time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	if !audit.HasWarnings() {
		t.Fatalf("expected world writable warning: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != bkReasonWorldWritable {
		t.Fatalf("expected world-writable: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.zip")
	if err := os.WriteFile(target, make([]byte, 64<<10), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "backups"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "backups", "link.zip")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerBackups(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != bkReasonSymlink {
		t.Fatalf("expected symlink block: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsBadName(t *testing.T) {
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "bad\x01name.zip"), 64<<10, 0o644, time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	if !audit.Blocking() || audit.Findings[0].Reason != bkReasonBadName {
		t.Fatalf("expected bad-name: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsDuplicate(t *testing.T) {
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "world.zip"), 64<<10, 0o644, time.Hour)
	writeBK(t, dir, filepath.Join("backups", "WORLD.zip"), 64<<10, 0o644, time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	dup := 0
	for _, f := range audit.Findings {
		if f.Reason == bkReasonDuplicate {
			dup++
		}
	}
	if dup != 1 {
		t.Fatalf("expected one duplicate finding: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsTooMany(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < bkMaxEntries+5; i++ {
		name := "world-" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".zip"
		writeBK(t, dir, filepath.Join("backups", name), 64<<10, 0o644, time.Hour)
	}
	audit := auditServerBackupsAt(dir, time.Now())
	if !audit.Blocking() {
		t.Fatalf("over budget must block: %+v", audit.Findings)
	}
	found := false
	for _, f := range audit.Findings {
		if f.Reason == bkReasonTooMany {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected too-many: %+v", audit.Findings)
	}
}

func TestAuditServerBackupsIgnoresNonArchive(t *testing.T) {
	dir := t.TempDir()
	writeBK(t, dir, filepath.Join("backups", "notes.txt"), 64<<10, 0o644, time.Hour)
	audit := auditServerBackupsAt(dir, time.Now())
	if len(audit.Backups) != 0 {
		t.Fatalf("txt should be ignored: %v", audit.Backups)
	}
	if audit.Summary() == "" || audit.Describe() == "" {
		t.Fatalf("describe/summary empty")
	}
}
