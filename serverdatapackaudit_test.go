package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writePackZip(t *testing.T, root, rel string, files []struct {
	Name string
	Body string
}) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	out, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer out.Close()
	writer := zip.NewWriter(out)
	for _, file := range files {
		entry, err := writer.Create(file.Name)
		if err != nil {
			t.Fatalf("zip entry: %v", err)
		}
		if _, err := entry.Write([]byte(file.Body)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
}

type packFile = struct {
	Name string
	Body string
}

func TestAuditServerDataPacksEmpty(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerDataPacks(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != dpReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksValid(t *testing.T) {
	dir := t.TempDir()
	meta := `{"pack":{"pack_format":15,"description":"ok"}}`
	writePackZip(t, dir, filepath.Join("datapacks", "good.zip"), []packFile{
		{Name: "pack.mcmeta", Body: meta},
		{Name: "data/example/functions/tick.mcfunction", Body: "say hi"},
	})
	audit := AuditServerDataPacks(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != dpReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksEntryEscape(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "evil.zip"), []packFile{
		{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":15}}`},
		{Name: "../../evil.sh", Body: "rm -rf"},
	})
	audit := AuditServerDataPacks(dir)
	if !audit.Blocking() {
		t.Fatalf("path escape must block: %+v", audit.Findings)
	}
	found := false
	for _, f := range audit.Findings {
		if f.Reason == dpReasonEntryEscape {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected entry-escape: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksBackslashEscape(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "bs.zip"), []packFile{
		{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":15}}`},
		{Name: `data\..\escape.json`, Body: "x"},
	})
	audit := AuditServerDataPacks(dir)
	if !audit.Blocking() {
		t.Fatalf("backslash entry must block: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksMissingMeta(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "nometa.zip"), []packFile{
		{Name: "data/example/functions/tick.mcfunction", Body: "say hi"},
	})
	audit := AuditServerDataPacks(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("missing meta should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != dpReasonMissingMcmeta {
		t.Fatalf("expected missing-mcmeta: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksInvalidMeta(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "badmeta.zip"), []packFile{
		{Name: "pack.mcmeta", Body: `{"pack":`},
	})
	audit := AuditServerDataPacks(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("invalid meta should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != dpReasonInvalidMcmeta {
		t.Fatalf("expected invalid-mcmeta: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksBadFormat(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "fmt.zip"), []packFile{
		{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":9999}}`},
	})
	audit := AuditServerDataPacks(dir)
	if audit.Findings[0].Reason != dpReasonInvalidMcmeta {
		t.Fatalf("expected invalid-mcmeta: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksBadDescription(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "desc.zip"), []packFile{
		{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":15,"description":"` + strings.Repeat("a", 300) + `"}}`},
	})
	audit := AuditServerDataPacks(dir)
	found := false
	for _, f := range audit.Findings {
		if f.Reason == dpReasonBadDescription {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected bad-description: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksBadZip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "datapacks"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "datapacks", "broken.zip"), []byte("not a zip"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	audit := AuditServerDataPacks(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != dpReasonBadZip {
		t.Fatalf("expected bad-zip: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.zip")
	writePackZip(t, dir, "real.zip", []packFile{{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":15}}`}})
	if err := os.Symlink(target, filepath.Join(dir, "datapacks", "link.zip")); err != nil {
		if err := os.MkdirAll(filepath.Join(dir, "datapacks"), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "datapacks", "link.zip")); err != nil {
			t.Skipf("symlink not supported: %v", err)
		}
	}
	audit := AuditServerDataPacks(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != dpReasonSymlink {
		t.Fatalf("expected symlink: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksTooManyEntries(t *testing.T) {
	dir := t.TempDir()
	files := []packFile{{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":15}}`}}
	for i := 0; i < dpMaxEntries+10; i++ {
		files = append(files, packFile{Name: "data/x/" + strings.Repeat("a", 4) + string(rune('a'+i%26)) + ".json", Body: "{}"})
	}
	writePackZip(t, dir, filepath.Join("datapacks", "huge.zip"), files)
	audit := AuditServerDataPacks(dir)
	if !audit.Blocking() {
		t.Fatalf("too many entries must block: %+v", audit.Findings)
	}
	seen := false
	for _, f := range audit.Findings {
		if f.Reason == dpReasonTooMany {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("expected too-many: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksDuplicateEntry(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "dup.zip"), []packFile{
		{Name: "pack.mcmeta", Body: `{"pack":{"pack_format":15}}`},
		{Name: "data/x.json", Body: "{}"},
		{Name: "DATA/X.JSON", Body: "{}"},
	})
	audit := AuditServerDataPacks(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("duplicate should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != dpReasonDuplicateName {
		t.Fatalf("expected duplicate-entry: %+v", audit.Findings)
	}
}

func TestAuditServerDataPacksDirectoryPack(t *testing.T) {
	dir := t.TempDir()
	packDir := filepath.Join(dir, "world", "datapacks", "manual")
	if err := os.MkdirAll(packDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	audit := AuditServerDataPacks(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("dir pack without meta should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != dpReasonMissingMcmeta {
		t.Fatalf("expected missing-mcmeta: %+v", audit.Findings)
	}
	if err := os.WriteFile(filepath.Join(packDir, "pack.mcmeta"), []byte(`{"pack":{"pack_format":15,"description":"ok"}}`), 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	clean := AuditServerDataPacks(dir)
	if clean.HasWarnings() || clean.Blocking() {
		t.Fatalf("dir pack should be clean: %+v", clean.Findings)
	}
}

func TestAuditServerDataPacksEmptyZip(t *testing.T) {
	dir := t.TempDir()
	writePackZip(t, dir, filepath.Join("datapacks", "empty.zip"), []packFile{})
	audit := AuditServerDataPacks(dir)
	codes := audit.Codes()
	hasEmpty := false
	for _, code := range codes {
		if code == dpReasonEmptyPack {
			hasEmpty = true
		}
	}
	if !hasEmpty {
		t.Fatalf("expected empty-pack: %v", codes)
	}
	if audit.Describe() == "" || audit.Summary() == "" {
		t.Fatalf("describe/summary empty")
	}
	_ = bytes.MinRead
}
