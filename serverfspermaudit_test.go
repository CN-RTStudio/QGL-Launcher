package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFSPermMissingDir(t *testing.T) {
	a := AuditServerFSPermissions(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("missing dir should not block")
	}
	if !auditHasReason(a, fsPermReasonMissing) {
		t.Fatalf("codes=%v", a.Codes())
	}
}

func TestFSPermEmptyServerDir(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerFSPermissions(dir)
	if len(a.Checked) != 1 {
		t.Fatalf("checked=%v", a.Checked)
	}
	if a.Blocking() {
		t.Fatalf("empty dir should not block")
	}
}

func TestFSPermCleanLayout(t *testing.T) {
	dir := t.TempDir()
	props := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(props, []byte("online-mode=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "plugins"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "world"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := AuditServerFSPermissions(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("clean layout flagged: %s", a.Describe())
	}
}

func TestFSPermWorldWritableConfigBlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(path, []byte("online-mode=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	if !auditHasReason(a, fsPermReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("want world-writable block, got %v", a.Codes())
	}
}

func TestFSPermGroupWritableWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ops.json")
	if err := os.WriteFile(path, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		t.Skipf("chmod unsupported: %v", err)
	}
	a := AuditServerFSPermissions(dir)
	if !auditHasReason(a, fsPermReasonGroupWritable) {
		t.Fatalf("want group-writable, got %v", a.Codes())
	}
	if a.Blocking() {
		t.Fatalf("group-writable should warn only")
	}
}

func TestFSPermWorldReadableSecretWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "whitelist.json")
	if err := os.WriteFile(path, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := AuditServerFSPermissions(dir)
	if !auditHasReason(a, fsPermReasonWorldReadable) {
		t.Fatalf("want world-readable, got %v", a.Codes())
	}
}

func TestFSPermExecutableConfigWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "eula.txt")
	if err := os.WriteFile(path, []byte("eula=true\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	a := AuditServerFSPermissions(dir)
	if !auditHasReason(a, fsPermReasonExecutable) {
		t.Fatalf("want executable-config, got %v", a.Codes())
	}
}
