package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const plaChan = "0123456789abcdef0123456789abcdef"

func plaWrite(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func plaNewDir(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "world", "playerdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func plaHas(a *PlyDataAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPlayerDataClean(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "01234567-89ab-cdef-0123-456789abcdef.dat", []byte{0x1f, 0x8b, 0x08, 0x00})
	a := AuditPlyDataFiles(root)
	if a.HasWarnings() {
		t.Fatalf("合法存档不应报警: %v", a.Describe())
	}
	if a.Files != 1 {
		t.Fatalf("应统计 1 个文件，实际 %d", a.Files)
	}
}

func TestPlayerDataMissingDir(t *testing.T) {
	a := AuditPlyDataFiles(t.TempDir())
	if !plaHas(a, plaMiss) {
		t.Fatalf("缺少目录应提示: %v", a.Describe())
	}
}

func TestPlayerDataEmptyDir(t *testing.T) {
	a := AuditPlyDataFiles("")
	if !plaHas(a, plaMiss) {
		t.Fatalf("空目录参数应提示: %v", a.Describe())
	}
}

func TestPlayerDataFallbackDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "playerdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	plaWrite(t, dir, "01234567-89ab-cdef-0123-456789abcdef.dat", []byte{0x1f, 0x8b})
	a := AuditPlyDataFiles(root)
	if a.HasWarnings() {
		t.Fatalf("回退目录不应报警: %v", a.Describe())
	}
}

func TestPlayerDataEmptyFile(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "aa.dat", nil)
	a := AuditPlyDataFiles(root)
	if !plaHas(a, plaFileEmpty) {
		t.Fatalf("空文件应提示: %v", a.Describe())
	}
}

func TestPlayerDataNotGzip(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "01234567-89ab-cdef-0123-456789abcdef.dat", []byte("PK not gzip"))
	a := AuditPlyDataFiles(root)
	if !plaHas(a, plaFileGzip) || !a.Blocking() {
		t.Fatalf("缺少 gzip 魔数应阻断: %v", a.Describe())
	}
}

func TestPlayerDataMalformedName(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "steve.dat", []byte{0x1f, 0x8b})
	a := AuditPlyDataFiles(root)
	if !plaHas(a, plaNameForm) {
		t.Fatalf("非 UUID 文件名应提示: %v", a.Describe())
	}
}

func TestPlayerDataBackupResidue(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "01234567-89ab-cdef-0123-456789abcdef.dat_old", []byte{0x1f, 0x8b})
	a := AuditPlyDataFiles(root)
	if !plaHas(a, plaBackup) {
		t.Fatalf("残留副本应提示: %v", a.Describe())
	}
	if a.Files != 0 {
		t.Fatalf("残留副本不计入有效文件: %d", a.Files)
	}
}

func TestPlayerDataOversized(t *testing.T) {
	root, dir := plaNewDir(t)
	big := make([]byte, 17*1024*1024)
	big[0], big[1] = 0x1f, 0x8b
	plaWrite(t, dir, "01234567-89ab-cdef-0123-456789abcdef.dat", big)
	a := AuditPlyDataFiles(root)
	if !plaHas(a, plaFileBig) {
		t.Fatalf("超大文件应提示: %v", a.Describe())
	}
}

func TestPlayerDataNonDatIgnored(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "readme.txt", []byte("hello"))
	a := AuditPlyDataFiles(root)
	if a.HasWarnings() {
		t.Fatalf("非 .dat 文件不应参与审计: %v", a.Describe())
	}
}

func TestPlayerDataDescribe(t *testing.T) {
	root, dir := plaNewDir(t)
	plaWrite(t, dir, "x.dat", []byte("bad"))
	desc := AuditPlyDataFiles(root).Describe()
	if !strings.Contains(desc, plaFileGzip) {
		t.Fatalf("描述应含原因: %s", desc)
	}
}
