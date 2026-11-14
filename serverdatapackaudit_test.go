package main

import (
	"archive/zip"
	"os"
	"path/filepath"
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
