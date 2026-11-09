package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFSPermWorldWritablePluginsBlocks(t *testing.T) {
	dir := t.TempDir()
	plugins := filepath.Join(dir, "plugins")
	if err := os.Mkdir(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(plugins, 0o777); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	if !fpHas(a, fsPermReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("want plugins world-writable block, got %v", a.Codes())
	}
}

func TestFSPermSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(real, []byte("online-mode=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	if !fpHas(a, fsPermReasonSymlink) || !a.Blocking() {
		t.Fatalf("want symlink block, got %v", a.Codes())
	}
}

func TestFSPermDirTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plugins"), []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := AuditServerFSPermissions(dir)
	if !fpHas(a, fsPermReasonNotRegular) {
		t.Fatalf("want not-regular, got %v", a.Codes())
	}
}

func TestFSPermSpecialBit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "banned-ips.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600|os.ModeSetuid); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	if !fpHas(a, fsPermReasonSpecialBit) {
		t.Fatalf("want special-bit, got %v", a.Codes())
	}
}

func TestFSPermCodesSortedUnique(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "world"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "world"), 0o777); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	path := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(path, []byte("online-mode=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	codes := a.Codes()
	if len(codes) < 2 {
		t.Fatalf("codes=%v", codes)
	}
	for i := 1; i < len(codes); i++ {
		if codes[i-1] > codes[i] {
			t.Fatalf("not sorted: %v", codes)
		}
	}
}

func TestFSPermDescribeStable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(path, []byte("online-mode=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	d1 := a.Describe()
	if d1 != a.Describe() {
		t.Fatalf("describe unstable")
	}
	if !strings.Contains(d1, "world-writable") {
		t.Fatalf("describe=%q", d1)
	}
}

func TestFSPermSummaryCountsChecked(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"server.properties", "eula.txt", "ops.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := AuditServerFSPermissions(dir)
	if !strings.Contains(a.Summary(), fmt.Sprintf("%d", len(a.Checked))) {
		t.Fatalf("summary=%q checked=%d", a.Summary(), len(a.Checked))
	}
}
