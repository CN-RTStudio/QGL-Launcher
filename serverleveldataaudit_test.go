package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func sldWrite(t *testing.T, dir string, payload []byte) {
	t.Helper()
	path := filepath.Join(dir, "world", "level.dat")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sldGzip(t *testing.T, inner string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(inner)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func sldHas(findings []LevelDataFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestLevelDataClean(t *testing.T) {
	dir := t.TempDir()
	sldWrite(t, dir, sldGzip(t, "\x0a\x00\x00Data\x08\x00\x09LevelName\x08\x00\x08Survival"))
	if a := AuditServerLevelData(dir); a.HasWarnings() {
		t.Fatalf("合法 level.dat 不应报警: %v", a.Describe())
	}
}

func TestLevelDataBadMagic(t *testing.T) {
	dir := t.TempDir()
	sldWrite(t, dir, []byte("not gzip data"))
	a := AuditServerLevelData(dir)
	if !a.Blocking() || !sldHas(a.Findings, sldReasonMagic) {
		t.Fatalf("非 gzip 头应阻断: %v", a.Describe())
	}
}

func TestLevelDataMissingData(t *testing.T) {
	dir := t.TempDir()
	sldWrite(t, dir, sldGzip(t, "\x08\x00\x09LevelName"))
	a := AuditServerLevelData(dir)
	if !sldHas(a.Findings, sldReasonNBT) {
		t.Fatalf("缺少 Data 根应报警: %v", a.Describe())
	}
}

func TestLevelDataNameControl(t *testing.T) {
	dir := t.TempDir()
	sldWrite(t, dir, sldGzip(t, "\x0a\x00\x00Data\x08\x00\x09LevelName\x08\x00\x03a\x07b"))
	a := AuditServerLevelData(dir)
	if !sldHas(a.Findings, sldReasonName) {
		t.Fatalf("世界名控制字符应报警: %v", a.Describe())
	}
}
