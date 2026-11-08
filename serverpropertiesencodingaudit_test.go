package main

import (
	"os"
	"path/filepath"
	"testing"
)

func setbWrite(t *testing.T, dir string, payload []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), payload, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func setbHas(findings []PropertiesEncodingFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPropertiesClean(t *testing.T) {
	dir := t.TempDir()
	setbWrite(t, dir, []byte("motd=A Minecraft Server\nmax-players=20\nonline-mode=true\n"))
	if a := AuditServerPropertiesEncoding(dir); a.HasWarnings() {
		t.Fatalf("合法属性文件不应报警: %v", a.Describe())
	}
}

func TestPropertiesBOM(t *testing.T) {
	dir := t.TempDir()
	setbWrite(t, dir, []byte("\xef\xbb\xbfmotd=x\n"))
	a := AuditServerPropertiesEncoding(dir)
	if !a.Blocking() || !setbHas(a.Findings, setbReasonBOM) {
		t.Fatalf("BOM 应阻断: %v", a.Describe())
	}
}

func TestPropertiesInvalidUTF8(t *testing.T) {
	dir := t.TempDir()
	setbWrite(t, dir, []byte("motd=\xff\xfe\n"))
	a := AuditServerPropertiesEncoding(dir)
	if !setbHas(a.Findings, setbReasonUTF8) {
		t.Fatalf("非法 UTF-8 应报警: %v", a.Describe())
	}
}

func TestPropertiesDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	setbWrite(t, dir, []byte("max-players=20\nmax-players=100\n"))
	a := AuditServerPropertiesEncoding(dir)
	if !setbHas(a.Findings, setbReasonDup) {
		t.Fatalf("重复键应报警: %v", a.Describe())
	}
}

func TestPropertiesNUL(t *testing.T) {
	dir := t.TempDir()
	setbWrite(t, dir, []byte("motd=a\x00b\n"))
	a := AuditServerPropertiesEncoding(dir)
	if !setbHas(a.Findings, setbReasonNUL) {
		t.Fatalf("NUL 字节应报警: %v", a.Describe())
	}
}
