package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rgnWrite(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func rgnNewDir(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "world", "region")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	return root, dir
}

func rgnHas(a *RgnFileAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func rgnSectorBuf() []byte {
	buf := make([]byte, 4096)
	return buf
}

func TestRegionClean(t *testing.T) {
	root, dir := rgnNewDir(t)
	rgnWrite(t, dir, "r.0.0.mca", rgnSectorBuf())
	a := AuditRgnFiles(root)
	if a.HasWarnings() {
		t.Fatalf("合法区域文件不应报警: %v", a.Describe())
	}
	if a.Files != 1 {
		t.Fatalf("应统计 1 个文件，实际 %d", a.Files)
	}
}

func TestRegionMissing(t *testing.T) {
	a := AuditRgnFiles(t.TempDir())
	if !rgnHas(a, rgnMiss) {
		t.Fatalf("缺少目录应提示: %v", a.Describe())
	}
}

func TestRegionEmptyDirArg(t *testing.T) {
	a := AuditRgnFiles("")
	if !rgnHas(a, rgnMiss) {
		t.Fatalf("空参数应提示: %v", a.Describe())
	}
}

func TestRegionFallbackDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "region")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	rgnWrite(t, dir, "r.0.0.mca", rgnSectorBuf())
	a := AuditRgnFiles(root)
	if a.HasWarnings() {
		t.Fatalf("回退目录不应报警: %v", a.Describe())
	}
}

func TestRegionEmptyFile(t *testing.T) {
	root, dir := rgnNewDir(t)
	rgnWrite(t, dir, "r.0.0.mca", nil)
	a := AuditRgnFiles(root)
	if !rgnHas(a, rgnFileEmpty) || !a.Blocking() {
		t.Fatalf("空文件应阻断: %v", a.Describe())
	}
}

func TestRegionShortHeader(t *testing.T) {
	root, dir := rgnNewDir(t)
	rgnWrite(t, dir, "r.0.0.mca", make([]byte, 100))
	a := AuditRgnFiles(root)
	if !rgnHas(a, rgnHeaderShort) || !a.Blocking() {
		t.Fatalf("头部不足应阻断: %v", a.Describe())
	}
}

func TestRegionUnaligned(t *testing.T) {
	root, dir := rgnNewDir(t)
	rgnWrite(t, dir, "r.0.0.mca", make([]byte, 5000))
	a := AuditRgnFiles(root)
	if !rgnHas(a, rgnFileAligned) {
		t.Fatalf("非扇区对齐应提示: %v", a.Describe())
	}
}

func TestRegionNameForm(t *testing.T) {
	root, dir := rgnNewDir(t)
	rgnWrite(t, dir, "region.mca", rgnSectorBuf())
	a := AuditRgnFiles(root)
	if !rgnHas(a, rgnNameForm) {
		t.Fatalf("命名异常应提示: %v", a.Describe())
	}
}

func TestRegionHeaderFlags(t *testing.T) {
	root, dir := rgnNewDir(t)
	buf := rgnSectorBuf()
	buf[0] = 0x01
	rgnWrite(t, dir, "r.0.0.mca", buf)
	a := AuditRgnFiles(root)
	if !rgnHas(a, rgnHeaderMagic) {
		t.Fatalf("非零偏移表应提示: %v", a.Describe())
	}
}

func TestRegionOversized(t *testing.T) {
	root, dir := rgnNewDir(t)
	buf := make([]byte, 65*1024*1024)
	rgnWrite(t, dir, "r.0.0.mca", buf)
	a := AuditRgnFiles(root)
	if !rgnHas(a, rgnFileBig) {
		t.Fatalf("超大文件应提示: %v", a.Describe())
	}
}

func TestRegionNonMcaIgnored(t *testing.T) {
	root, dir := rgnNewDir(t)
	rgnWrite(t, dir, "notes.txt", []byte("hello"))
	a := AuditRgnFiles(root)
	if a.HasWarnings() {
		t.Fatalf("非 .mca 不应参与审计: %v", a.Describe())
	}
}

func TestRegionDescribe(t *testing.T) {
	a := AuditRgnFiles(t.TempDir())
	if !strings.Contains(a.Describe(), rgnMiss) {
		t.Fatalf("描述应含原因键: %s", a.Describe())
	}
}

func TestRegionSectorConstant(t *testing.T) {
	if fmt.Sprintf("%d", rgnSector) != "4096" {
		t.Fatalf("扇区常量应为 4096")
	}
}
