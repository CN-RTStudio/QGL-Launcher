package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func serverListTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if runtime.GOOS == "windows" {
		root = filepath.Join(root, "QGL")
	}
	return root
}

func TestImportServerListTextAcceptsAndDedupes(t *testing.T) {
	existing := []SavedServerEntry{{Name: "keep", Host: "mc.example.org", Port: 25565}}
	res := ImportServerListText("主服 mc.example.org\n备用 10.0.0.8:25566\n坏地址 a b c\n", existing, time.Unix(1700000000, 0))
	if len(res.Accepted) != 1 {
		t.Fatalf("expected exactly one accepted entry, got %d (%s)", len(res.Accepted), DescribeServerListImport(res))
	}
	if res.Duplicates != 1 {
		t.Fatalf("expected one duplicate, got %d", res.Duplicates)
	}
	if len(res.Rejected) == 0 {
		t.Fatalf("expected malformed line to be rejected")
	}
	if res.Private != 1 || len(res.Warnings) != 1 {
		t.Fatalf("expected one private warning, got private=%d warnings=%d", res.Private, len(res.Warnings))
	}
	entry := res.Accepted[0]
	if entry.Host != "10.0.0.8" || entry.Port != 25566 {
		t.Fatalf("unexpected accepted entry: %+v", entry)
	}
	if entry.Kind != "private" {
		t.Fatalf("expected private kind, got %s", entry.Kind)
	}
	if entry.AddedAt != 1700000000 || entry.Name != "备用" {
		t.Fatalf("import metadata not preserved: %+v", entry)
	}
}

func TestImportServerListTextRejectsSchemeLines(t *testing.T) {
	res := ImportServerListText("x https://evil.example/mc\n", nil, time.Now())
	if len(res.Accepted) != 0 {
		t.Fatalf("scheme line must not be accepted: %+v", res.Accepted)
	}
	if len(res.Rejected) == 0 {
		t.Fatalf("expected rejection record")
	}
}

func TestNormalizeSavedServerEntryBounds(t *testing.T) {
	cases := []SavedServerEntry{
		{Host: "", Port: 25565},
		{Host: "mc.example.org", Port: 0},
		{Host: "mc.example.org", Port: 70000},
		{Host: strings.Repeat("a", 300), Port: 25565},
		{Host: "mc.example.org", Port: 25565, Name: "\x00bad"},
	}
	for _, entry := range cases {
		if _, err := normalizeSavedServerEntry(entry); err == nil {
			t.Fatalf("expected rejection for %+v", entry)
		}
	}
	clean, err := normalizeSavedServerEntry(SavedServerEntry{Name: "\x01\x02", Host: "MC.Example.ORG", Port: 25565})
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if clean.Name != "MC.Example.ORG" {
		t.Fatalf("expected host fallback name, got %q", clean.Name)
	}
}

func TestWriteReadServerListStoreRoundTrip(t *testing.T) {
	root := serverListTestRoot(t)
	path := filepath.Join(root, "servers.json")
	if _, err := ReadServerListStore(path, root); err != nil {
		t.Fatalf("missing store should read as empty: %v", err)
	}
	entries := []SavedServerEntry{
		{Name: "公网", Host: "mc.example.org", Port: 25565},
		{Name: "局域网", Host: "192.168.1.20", Port: 25566},
		{Name: "重复", Host: "mc.example.org", Port: 25565},
	}
	if err := WriteServerListStore(path, root, entries, time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
	}
	store, err := ReadServerListStore(path, root)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if store.Version != serverListStoreVersion || len(store.Entries) != 2 {
		t.Fatalf("unexpected store shape: %+v", store)
	}
	if store.Entries[1].Kind != "private" {
		t.Fatalf("expected private kind, got %s", store.Entries[1].Kind)
	}
}

func TestServerListStoreRejectsPathEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "servers.json")
	if _, err := ReadServerListStore(outside, root); err == nil {
		t.Fatalf("read outside root must fail")
	}
	if err := WriteServerListStore(outside, root, nil, time.Now()); err == nil {
		t.Fatalf("write outside root must fail")
	}
}

func TestWriteServerListStoreRejectsInvalidEntry(t *testing.T) {
	root := serverListTestRoot(t)
	path := filepath.Join(root, "servers.json")
	err := WriteServerListStore(path, root, []SavedServerEntry{{Host: "bad host", Port: 25565}}, time.Now())
	if err == nil {
		t.Fatalf("invalid host must be rejected")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatalf("rejected write must not leave a file behind")
	}
}

func TestWriteServerListStoreCapsEntries(t *testing.T) {
	root := serverListTestRoot(t)
	path := filepath.Join(root, "servers.json")
	entries := make([]SavedServerEntry, 0, serverListStoreMaxEntry+4)
	for i := 0; i < serverListStoreMaxEntry+4; i++ {
		entries = append(entries, SavedServerEntry{Host: fmt.Sprintf("h%d.example.org", i), Port: 25565})
	}
	if err := WriteServerListStore(path, root, entries, time.Now()); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	store, err := ReadServerListStore(path, root)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(store.Entries) > serverListStoreMaxEntry {
		t.Fatalf("entry cap not enforced: %d", len(store.Entries))
	}
}

func TestServerListStoreRejectsSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "QGL")
	if err := os.MkdirAll(filepath.Join(root, "QGL"), 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	storePath := filepath.Join(root, "QGL", "servers.json")
	outsideFile := filepath.Join(outside, "servers.json")
	if err := os.WriteFile(outsideFile, []byte(`{"version":1,"entries":[]}`), 0o600); err != nil {
		t.Fatalf("seed outside store: %v", err)
	}
	if err := os.Symlink(outsideFile, storePath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := ReadServerListStore(storePath, root); err == nil {
		t.Fatalf("symlinked server list store outside root was read")
	}
	if err := WriteServerListStore(storePath, root, nil, time.Now()); err == nil {
		t.Fatalf("symlinked server list store outside root was written")
	}
	if info, statErr := os.Lstat(outsideFile); statErr != nil {
		t.Fatalf("outside store disappeared: %v", statErr)
	} else if info.Size() != int64(len(`{"version":1,"entries":[]}`)) {
		t.Fatalf("outside store was modified, size=%d", info.Size())
	}
}

func TestServerListStoreAcceptsRegularPath(t *testing.T) {
	root := serverListTestRoot(t)
	storePath := serverListStorePath(root)
	previousWD, wdErr := os.Getwd()
	if wdErr != nil {
		t.Fatalf("getwd: %v", wdErr)
	}
	scratch := t.TempDir()
	if chdirErr := os.Chdir(scratch); chdirErr != nil {
		t.Fatalf("chdir: %v", chdirErr)
	}
	defer func() {
		if restoreErr := os.Chdir(previousWD); restoreErr != nil {
			t.Fatalf("restore cwd: %v", restoreErr)
		}
	}()
	if err := WriteServerListStore(storePath, root, nil, time.Now()); err != nil {
		t.Fatalf("write regular store: %v", err)
	}
	if _, statErr := os.Stat(storePath); statErr != nil {
		t.Fatalf("store not written under root: %v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(scratch, "QGL", "servers.json")); statErr == nil {
		t.Fatalf("store written relative to process cwd")
	}
	store, err := ReadServerListStore(storePath, root)
	if err != nil {
		t.Fatalf("read regular store: %v", err)
	}
	if store.Version != serverListStoreVersion {
		t.Fatalf("store version = %d, want %d", store.Version, serverListStoreVersion)
	}
}

func TestServerListStoreRejectsSymlinkDirectory(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "QGL")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	inner := filepath.Join(root, "QGL")
	if err := os.Symlink(outside, inner); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	storePath := filepath.Join(inner, "servers.json")
	if _, err := ReadServerListStore(storePath, root); err == nil {
		t.Fatalf("server list store under symlinked directory was read")
	}
	if err := WriteServerListStore(storePath, root, nil, time.Now()); err == nil {
		t.Fatalf("server list store under symlinked directory was written")
	}
	if _, statErr := os.Lstat(filepath.Join(outside, "servers.json")); statErr == nil {
		t.Fatalf("store file created outside root via symlinked directory")
	}
}

func TestNormalizeSavedServerEntryRejectsFormatRunes(t *testing.T) {
	in := SavedServerEntry{Name: "ok", Host: "evil\u202e.example.com", Port: 25565}
	if _, err := normalizeSavedServerEntry(in); err == nil {
		t.Fatalf("saved host with bidi override accepted")
	}
	in = SavedServerEntry{Name: "ok", Host: "evil\u0085.example.com", Port: 25565}
	if _, err := normalizeSavedServerEntry(in); err == nil {
		t.Fatalf("saved host with C1 control accepted")
	}
	good := SavedServerEntry{Name: "Hypixel\u202eevil", Host: "play.example.com", Port: 25565}
	out, err := normalizeSavedServerEntry(good)
	if err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if out.Name != "Hypixelevil" {
		t.Fatalf("saved name = %q, want sanitized name", out.Name)
	}
}
