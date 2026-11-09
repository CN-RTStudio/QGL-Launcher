package main

import (
	"os"
	"path/filepath"
	"testing"
)

func playerWorld(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range playerDataSubdirs {
		if err := os.MkdirAll(filepath.Join(root, name), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
	}
	return root
}

func TestAuditWorldPlayerDataAbsent(t *testing.T) {
	audit, err := AuditWorldPlayerData(t.TempDir())
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Present || audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("empty world must be silent: %s", audit.Describe())
	}
}

func TestAuditWorldPlayerDataClean(t *testing.T) {
	root := playerWorld(t)
	if err := os.WriteFile(filepath.Join(root, "playerdata", "77777777777777777777777777777777.dat"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write dat: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "stats", "88888888-8888-8888-8888-888888888888.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write stats: %v", err)
	}
	audit, err := AuditWorldPlayerData(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Files != 2 {
		t.Fatalf("expected two files, got %d", audit.Files)
	}
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("clean player data must pass: %s", audit.Describe())
	}
}

func TestAuditWorldPlayerDataBadNameWarns(t *testing.T) {
	root := playerWorld(t)
	if err := os.WriteFile(filepath.Join(root, "playerdata", "not-a-uuid.dat"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit, err := AuditWorldPlayerData(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("bad name must warn only: %s", audit.Describe())
	}
}

func TestAuditWorldPlayerDataSymlinkBlocks(t *testing.T) {
	root := playerWorld(t)
	real := filepath.Join(root, "real.dat")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(root, "playerdata", "99999999999999999999999999999999.dat")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditWorldPlayerData(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("symlinked playerdata must block: %s", audit.Describe())
	}
}

func TestAuditWorldPlayerDataNestedDirBlocks(t *testing.T) {
	root := playerWorld(t)
	if err := os.Mkdir(filepath.Join(root, "stats", "nested"), 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	audit, err := AuditWorldPlayerData(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("nested directory must block: %s", audit.Describe())
	}
}

func TestAuditWorldPlayerDataSymlinkedSubdirBlocks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "playerdata")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	audit, err := AuditWorldPlayerData(root)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("symlinked playerdata dir must block: %s", audit.Describe())
	}
}

func TestValidPlayerDataNameVariants(t *testing.T) {
	cases := []struct {
		dir   string
		name  string
		valid bool
	}{
		{"playerdata", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat", true},
		{"playerdata", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat_old", true},
		{"playerdata", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.DAT", true},
		{"playerdata", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.dat", true},
		{"playerdata", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat", false},
		{"playerdata", "player.dat", false},
		{"stats", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json", true},
		{"stats", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json.bak", false},
		{"advancements", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.json", true},
		{"advancements", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", false},
	}
	for _, item := range cases {
		if got := validPlayerDataName(item.dir, item.name); got != item.valid {
			t.Fatalf("validPlayerDataName(%s, %s) = %v, want %v", item.dir, item.name, got, item.valid)
		}
	}
}
