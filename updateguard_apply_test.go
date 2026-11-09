package main

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestInspectUpdateZipPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("../evil.exe") // Zip Slip
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{})
	if v.OK {
		t.Fatal("zip slip must be rejected")
	}
	if len(v.Findings) == 0 || v.Findings[0].Code != "zip-unsafe-path" {
		t.Fatalf("expected unsafe-path finding, got %v", v.Findings)
	}
}

func TestInspectUpdateZipNoLauncher(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("OpenQGL/data.txt")
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{})
	if v.OK {
		t.Fatal("zip without launcher entry must be rejected")
	}
}

func TestInspectUpdateZipMultiRoot(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	zw.Create("a/QingLongLauncher.exe")
	zw.Create("b/data.txt")
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{})
	if v.OK {
		t.Fatal("multi-root zip must be rejected")
	}
}

func TestInspectUpdateZipEntryOverflow(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 30; i++ {
		zw.Create("OpenQGL/f" + strings.Repeat("0", i) + ".dat")
	}
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	v := InspectUpdateZip(zr, UpdateLimits{ZipEntriesMax: 10})
	if v.OK {
		t.Fatal("entry overflow must be rejected")
	}
	if v.Findings[0].Code != "zip-entries-overflow" {
		t.Fatalf("unexpected code %v", v.Findings[0])
	}
}

func TestHasControlCharStr(t *testing.T) {
	if hasControlCharStr("clean-name") {
		t.Fatal("clean name flagged")
	}
	if !hasControlCharStr("a\u0000b") {
		t.Fatal("NUL not flagged")
	}
	if !hasControlCharStr("a\nb") {
		t.Fatal("newline not flagged")
	}
}

func TestUniqueStrings(t *testing.T) {
	got := uniqueStrings([]string{"b", "a", "b", "c", ""})
	if strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("uniqueStrings got %v", got)
	}
}

func TestReadZipEntryTextBounded(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("note.txt")
	w.Write([]byte("hello world"))
	zw.Close()
	zr, _ := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	text, err := readZipEntryText(zr.File[0], 100)
	if err != nil || text != "hello world" {
		t.Fatalf("read text err=%v text=%q", err, text)
	}
	if _, err := readZipEntryText(zr.File[0], 5); err == nil {
		t.Fatal("bounded read should fail beyond limit")
	}
}
