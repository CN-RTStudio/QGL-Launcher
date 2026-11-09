package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func iconChunk(kind string, body []byte) []byte {
	out := make([]byte, 0, 12+len(body))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(body)))
	out = append(out, length[:]...)
	out = append(out, []byte(kind)...)
	out = append(out, body...)
	out = append(out, 0, 0, 0, 0)
	return out
}

func iconPNG(width, height uint32, colorType byte, idatLen int, trailing []byte, withIEND bool) []byte {
	out := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:4], width)
	binary.BigEndian.PutUint32(ihdr[4:8], height)
	ihdr[8] = 8
	ihdr[9] = colorType
	out = append(out, iconChunk("IHDR", ihdr)...)
	out = append(out, iconChunk("IDAT", bytes.Repeat([]byte{0}, idatLen))...)
	if withIEND {
		out = append(out, iconChunk("IEND", nil)...)
	}
	out = append(out, trailing...)
	return out
}

func writeIcon(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write icon: %v", err)
	}
}

func TestAuditServerIconEmptyDir(t *testing.T) {
	dir := t.TempDir()
	audit := AuditServerIcon(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != iconReasonOK {
		t.Fatalf("unexpected findings: %+v", audit.Findings)
	}
}

func TestAuditServerIconValid(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(64, 64, 6, 40, nil, true))
	audit := AuditServerIcon(dir)
	if len(audit.Findings) != 1 || audit.Findings[0].Reason != iconReasonOK {
		t.Fatalf("expected clean icon: %+v", audit.Findings)
	}
}

func TestAuditServerIconBadSignature(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", []byte("GIF89a......"))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonBadType {
		t.Fatalf("expected bad-type: %+v", audit.Findings)
	}
}

func TestAuditServerIconTruncated(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(64, 64, 6, 40, nil, false))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonTruncated {
		t.Fatalf("expected truncated: %+v", audit.Findings)
	}
}

func TestAuditServerIconOversized(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(1024, 1024, 6, 40, nil, true))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonOversized {
		t.Fatalf("expected oversized: %+v", audit.Findings)
	}
}

func TestAuditServerIconNonstandardSize(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(32, 32, 6, 40, nil, true))
	audit := AuditServerIcon(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("nonstandard size should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != iconReasonNonstandardSize {
		t.Fatalf("expected nonstandard-size: %+v", audit.Findings)
	}
}

func TestAuditServerIconBadColorType(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(64, 64, 9, 40, nil, true))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonBadColorType {
		t.Fatalf("expected bad-color-type: %+v", audit.Findings)
	}
}

func TestAuditServerIconTrailingData(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(64, 64, 6, 40, []byte("PK"), true))
	audit := AuditServerIcon(dir)
	if audit.Blocking() || !audit.HasWarnings() {
		t.Fatalf("trailing bytes should warn: %+v", audit.Findings)
	}
	if audit.Findings[0].Reason != iconReasonTrailingData {
		t.Fatalf("expected trailing-data: %+v", audit.Findings)
	}
}

func TestAuditServerIconSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skipf("symlink requires privileges on windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.png")
	if err := os.WriteFile(target, iconPNG(64, 64, 6, 40, nil, true), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "server-icon.png")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonSymlink {
		t.Fatalf("expected symlink: %+v", audit.Findings)
	}
}

func TestAuditServerIconTooLarge(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", bytes.Repeat([]byte{'A'}, iconMaxFileBytes+1))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonTooLarge {
		t.Fatalf("expected too-large: %+v", audit.Findings)
	}
}

func TestAuditServerIconBadChunk(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconChunk("ihdr", make([]byte, 13)))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonBadType {
		t.Fatalf("expected signature failure first: %+v", audit.Findings)
	}
}

func TestAuditServerIconInflateBomb(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", iconPNG(64, 64, 6, 1, nil, true))
	audit := AuditServerIcon(dir)
	if !audit.Blocking() || audit.Findings[0].Reason != iconReasonInflateBomb {
		t.Fatalf("expected inflate-bomb: %+v", audit.Findings)
	}
}

func TestIconDescribeTruncates(t *testing.T) {
	dir := t.TempDir()
	writeIcon(t, dir, "server-icon.png", []byte("not png at all"))
	audit := AuditServerIcon(dir)
	if len(audit.Findings) == 0 {
		t.Fatalf("expected finding")
	}
	if !strings.Contains(audit.Describe(), "server-icon.png") {
		t.Fatalf("describe missing file: %s", audit.Describe())
	}
	if audit.Summary() == "" {
		t.Fatalf("summary empty")
	}
}
