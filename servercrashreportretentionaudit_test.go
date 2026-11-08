package main

import (
	"os"
	"path/filepath"
	"testing"
)

func scgWrite(t *testing.T, dir, name, content string) {
	t.Helper()
	base := filepath.Join(dir, "crash-reports")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func scgHas(findings []CrashReportHygieneFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestCrashReportsMissing(t *testing.T) {
	if a := AuditServerCrashReports(t.TempDir()); a.Blocking() {
		t.Fatalf("缺少目录不应阻断: %v", a.Describe())
	}
}

func TestCrashReportsClean(t *testing.T) {
	dir := t.TempDir()
	scgWrite(t, dir, "crash-2024-01-01_00.00.00-server.txt", "Description: test\n")
	if a := AuditServerCrashReports(dir); a.HasWarnings() {
		t.Fatalf("普通报告不应报警: %v", a.Describe())
	}
}

func TestCrashReportsSeed(t *testing.T) {
	dir := t.TempDir()
	scgWrite(t, dir, "crash-2024-01-01_00.00.00-server.txt", "level-seed=12345\n")
	a := AuditServerCrashReports(dir)
	if !scgHas(a.Findings, scgReasonSeed) {
		t.Fatalf("种子泄漏应报警: %v", a.Describe())
	}
}

func TestCrashReportsSecret(t *testing.T) {
	dir := t.TempDir()
	scgWrite(t, dir, "crash-2024-01-01_00.00.00-server.txt", "Authorization: Bearer abc\n")
	a := AuditServerCrashReports(dir)
	if !a.Blocking() || !scgHas(a.Findings, scgReasonToken) {
		t.Fatalf("凭据泄漏应阻断: %v", a.Describe())
	}
}
