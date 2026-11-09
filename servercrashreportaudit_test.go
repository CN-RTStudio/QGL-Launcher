package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func crWrite(t *testing.T, dir, rel, body string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func crHasReason(audit CrashReportAudit, reason string) bool {
	for _, f := range audit.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestCrashReportMissingDirectoryBlocks(t *testing.T) {
	audit := AuditCrashReports(filepath.Join(t.TempDir(), "absent"))
	if !audit.Blocking() {
		t.Fatal("missing server directory must block")
	}
	if !crHasReason(audit, crReasonMissing) {
		t.Fatal("missing reason not reported")
	}
}

func TestCrashReportNoDirectoryPasses(t *testing.T) {
	audit := AuditCrashReports(t.TempDir())
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
	if !crHasReason(audit, crReasonOK) {
		t.Fatal("missing crash-reports should be reported as info")
	}
}

func TestCrashReportCleanFilePasses(t *testing.T) {
	dir := t.TempDir()
	crWrite(t, dir, "crash-reports/crash-2026-11-01_10.00.00-server.txt", "java.lang.RuntimeException\nat net.minecraft.Server.run\n")
	audit := AuditCrashReports(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("unexpected findings: %s", audit.Describe())
	}
	if len(audit.Files) != 1 {
		t.Fatalf("expected one file, got %v", audit.Files)
	}
}

func TestCrashReportPlaintextPasswordBlocks(t *testing.T) {
	dir := t.TempDir()
	crWrite(t, dir, "crash-reports/crash-1.txt", "rcon.password=supersecret\n")
	audit := AuditCrashReports(dir)
	if !audit.Blocking() {
		t.Fatal("plaintext password must block")
	}
	if !crHasReason(audit, crReasonSecret) {
		t.Fatal("secret reason not reported")
	}
}

func TestCrashReportBearerTokenBlocks(t *testing.T) {
	dir := t.TempDir()
	crWrite(t, dir, "crash-reports/crash-2.txt", "Authorization: Bearer eyJhbGciOi\n")
	audit := AuditCrashReports(dir)
	if !crHasReason(audit, crReasonSecret) {
		t.Fatal("bearer token not reported")
	}
}

func TestCrashReportHomePathWarns(t *testing.T) {
	dir := t.TempDir()
	crWrite(t, dir, "crash-reports/crash-3.txt", "at /home/alice/.minecraft/mods/x.jar\n")
	audit := AuditCrashReports(dir)
	if audit.Blocking() {
		t.Fatalf("home path must not block: %s", audit.Describe())
	}
	if !crHasReason(audit, crReasonHomePath) {
		t.Fatal("home path not reported")
	}
}

func TestCrashReportStaleWarns(t *testing.T) {
	dir := t.TempDir()
	crWrite(t, dir, "crash-reports/crash-2020-01-01_00.00.00-server.txt", "boom\n")
	audit := auditCrashReportsAt(dir, time.Date(2026, 11, 7, 12, 0, 0, 0, time.Local))
	if audit.Blocking() {
		t.Fatalf("stale report must not block: %s", audit.Describe())
	}
	if !crHasReason(audit, crReasonStale) {
		t.Fatal("stale report not reported")
	}
}

func TestCrashReportBadExtensionWarns(t *testing.T) {
	dir := t.TempDir()
	crWrite(t, dir, "crash-reports/crash.exe", "MZ")
	audit := AuditCrashReports(dir)
	if !crHasReason(audit, crReasonBadName) {
		t.Fatal("bad extension not reported")
	}
}

func TestCrashReportOversizedBlocks(t *testing.T) {
	dir := t.TempDir()
	body := make([]byte, crMaxFileBytes+16)
	crWrite(t, dir, "crash-reports/huge.txt", string(body))
	audit := AuditCrashReports(dir)
	if !crHasReason(audit, crReasonTooLarge) {
		t.Fatal("oversized report not reported")
	}
}

func TestCrashReportSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "crash-reports"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := crWrite(t, dir, "outside.txt", "boom\n")
	if err := os.Symlink(target, filepath.Join(dir, "crash-reports", "link.txt")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	audit := AuditCrashReports(dir)
	if !crHasReason(audit, crReasonSymlink) {
		t.Fatal("symlink not reported")
	}
}

func TestCrashReportWorldWritableBlocks(t *testing.T) {
	dir := t.TempDir()
	path := crWrite(t, dir, "crash-reports/crash-4.txt", "boom\n")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	audit := AuditCrashReports(dir)
	if !crHasReason(audit, crReasonWorldWritable) {
		t.Fatal("world writable not reported")
	}
}

func TestCrashReportTooManyBlocks(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "crash-reports"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for i := 0; i < crMaxFiles+4; i++ {
		if err := os.WriteFile(filepath.Join(dir, "crash-reports", "c"+itoaPJ(i)+".txt"), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	audit := AuditCrashReports(dir)
	if !crHasReason(audit, crReasonTooMany) {
		t.Fatal("too many reports not reported")
	}
}

func TestCrashReportDescribeSkipsOK(t *testing.T) {
	audit := CrashReportAudit{}
	audit.add("", crReasonOK, "fine", false)
	if audit.Describe() != "崩溃报告未发现风险" {
		t.Fatalf("unexpected describe: %s", audit.Describe())
	}
}
