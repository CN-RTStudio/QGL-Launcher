package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadStartupScriptRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sh")
	if err := os.WriteFile(target, []byte("echo hi\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := readStartupScript(link); err == nil {
		t.Fatalf("符号链接脚本未被拒绝")
	}
}

func TestReadStartupScriptRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := readStartupScript(dir); err == nil {
		t.Fatalf("目录未被拒绝")
	}
}

func TestPruneCrashReportsKeepsRecent(t *testing.T) {
	mcDir := t.TempDir()
	crashDir := filepath.Join(mcDir, "crash-reports")
	if err := os.MkdirAll(crashDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		name := filepath.Join(crashDir, "crash-"+string(rune('a'+i))+".txt")
		if err := os.WriteFile(name, []byte("report\n"), 0o600); err != nil {
			t.Fatalf("write report: %v", err)
		}
		mod := now.Add(time.Duration(i) * time.Minute)
		if err := os.Chtimes(name, mod, mod); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	removed, err := pruneCrashReports(mcDir, 1, now.AddDate(0, 0, -30))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed=%d want 2", removed)
	}
	left, err := os.ReadDir(crashDir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(left) != 1 {
		t.Fatalf("剩余文件=%d want 1", len(left))
	}
}

func TestPruneCrashReportsSkipsSymlink(t *testing.T) {
	mcDir := t.TempDir()
	crashDir := filepath.Join(mcDir, "crash-reports")
	if err := os.MkdirAll(crashDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(mcDir, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	link := filepath.Join(crashDir, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := pruneCrashReports(mcDir, 0, time.Now()); err != nil {
		t.Fatalf("prune: %v", err)
	}
	if _, err := os.Lstat(outside); err != nil {
		t.Fatalf("外部文件被误删: %v", err)
	}
}
