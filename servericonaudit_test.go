package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func sicPNG(width, height uint32) []byte {
	data := make([]byte, 0, 40)
	data = append(data, 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a)
	chunk := make([]byte, 0, 25)
	chunk = append(chunk, 0, 0, 0, 13)
	chunk = append(chunk, 'I', 'H', 'D', 'R')
	chunk = append(chunk, make([]byte, 8)...)
	binary.BigEndian.PutUint32(chunk[8:12], width)
	binary.BigEndian.PutUint32(chunk[12:16], height)
	chunk = append(chunk, 8, 6, 0, 0, 0)
	data = append(data, chunk...)
	return data
}

func sicWrite(t *testing.T, dir, rel string, data []byte) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sicHas(findings []IconFileFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestIconMissing(t *testing.T) {
	a := AuditServerIconFile(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少图标不应报警: %v", a.Describe())
	}
}

func TestIconStandard(t *testing.T) {
	dir := t.TempDir()
	sicWrite(t, dir, "server-icon.png", sicPNG(64, 64))
	a := AuditServerIconFile(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("标准图标不应报警: %v", a.Describe())
	}
}

func TestIconNotPNG(t *testing.T) {
	dir := t.TempDir()
	sicWrite(t, dir, "server-icon.png", []byte("<html>evil</html>"))
	a := AuditServerIconFile(dir)
	if !a.Blocking() || !sicHas(a.Findings, sicReasonMagic) {
		t.Fatalf("非 PNG 应阻断: %v", a.Describe())
	}
}

func TestIconOversized(t *testing.T) {
	dir := t.TempDir()
	sicWrite(t, dir, "server-icon.png", sicPNG(2048, 2048))
	a := AuditServerIconFile(dir)
	if !a.Blocking() || !sicHas(a.Findings, sicReasonSide) {
		t.Fatalf("超大图标应阻断: %v", a.Describe())
	}
}

func TestIconNonStandardSize(t *testing.T) {
	dir := t.TempDir()
	sicWrite(t, dir, "server-icon.png", sicPNG(128, 128))
	a := AuditServerIconFile(dir)
	if a.Blocking() || !sicHas(a.Findings, sicReasonSize) {
		t.Fatalf("非 64x64 应告警: %v", a.Describe())
	}
}

func TestIconSymlink(t *testing.T) {
	dir := t.TempDir()
	sicWrite(t, dir, "real.png", sicPNG(64, 64))
	if err := os.Symlink(filepath.Join(dir, "real.png"), filepath.Join(dir, "server-icon.png")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerIconFile(dir)
	if !a.Blocking() || !sicHas(a.Findings, sicReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
