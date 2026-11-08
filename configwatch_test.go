package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordAndDiffFingerprints(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "instance.json")
	p2 := filepath.Join(dir, "options.txt")
	if err := os.WriteFile(p1, []byte(`{"name":"a","version":"1.20","javaPath":"j"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("soundOn=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lim := defaultWatchLimits()
	cur, err := recordFingerprint([]string{p1, p2}, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur.Files) != 2 || cur.Files[0].UMFS == "" || cur.Files[1].UMFS == "" {
		t.Fatalf("bad record: %+v", cur.Files)
	}
	d := diffFingerprints(fingerprintRecord{}, cur)
	if d.OK || len(d.New) != 2 {
		t.Fatalf("expected 2 new, got ok=%v new=%v", d.OK, d.New)
	}
	// 改内容 → changed
	if err := os.WriteFile(p1, []byte(`{"name":"b","version":"1.20","javaPath":"j"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cur2, err := recordFingerprint([]string{p1, p2}, lim)
	if err != nil {
		t.Fatal(err)
	}
	d2 := diffFingerprints(cur, cur2)
	if d2.OK || len(d2.Changed) != 1 || d2.Changed[0] != p1 {
		t.Fatalf("expected changed p1, got %+v", d2)
	}
	// 删文件 → missing
	os.Remove(p1)
	cur3, _ := recordFingerprint([]string{p1, p2}, lim)
	d3 := diffFingerprints(cur2, cur3)
	if d3.OK || len(d3.Missing) != 1 || d3.Missing[0] != p1 {
		t.Fatalf("expected missing p1, got %+v", d3)
	}
}

func TestFingerprintRecordRoundTrip(t *testing.T) {
	dir := t.TempDir()
	recPath := filepath.Join(dir, "watch.json")
	lim := defaultWatchLimits()
	rec := fingerprintRecord{Files: []fileFingerprint{{Path: "a", UMFS: "deadbeef"}, {Path: "b", UMFS: ""}}}
	if err := saveFingerprintRecord(recPath, rec, lim); err != nil {
		t.Fatal(err)
	}
	got, err := loadFingerprintRecord(recPath, lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Files) != 2 || got.Files[1].Path != "b" || got.Files[1].UMFS != "" {
		t.Fatalf("round trip mismatch: %+v", got.Files)
	}
}

func TestWatchLimitsEnforced(t *testing.T) {
	lim := WatchLimits{MaxRecordBytes: 32, MaxFiles: 1}
	rec := fingerprintRecord{Files: []fileFingerprint{
		{Path: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UMFS: "x"},
		{Path: "b", UMFS: "y"},
	}}
	dir := t.TempDir()
	if err := saveFingerprintRecord(filepath.Join(dir, "w.json"), rec, lim); err == nil {
		t.Fatalf("expected record-too-large error")
	}
	if _, err := recordFingerprint([]string{"a", "b", "c"}, lim); err == nil {
		t.Fatalf("expected files-overflow error")
	}
}

func TestSummarizeWatchDiff(t *testing.T) {
	d := watchDiff{OK: false, Changed: []string{"a"}, Missing: []string{"b"}, New: nil}
	s := SummarizeWatchDiff(d)
	if s != "configwatch bad changed:a" {
		t.Fatalf("unexpected summary: %s", s)
	}
	ok := watchDiff{OK: true}
	if SummarizeWatchDiff(ok) != "configwatch ok changed=0 missing=0 new=0" {
		t.Fatalf("unexpected ok summary: %s", SummarizeWatchDiff(ok))
	}
}
