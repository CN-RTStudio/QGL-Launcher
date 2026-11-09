package main

import (
	"os"
	"path/filepath"
	"testing"
)

func swnWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func swnHas(findings []WorldNameFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestWorldNameMissingProps(t *testing.T) {
	a := AuditServerWorldName(t.TempDir())
	if !swnHas(a.Findings, swnReasonNoProps) {
		t.Fatalf("期望缺少属性告警: %v", a.Describe())
	}
}

func TestWorldNameClean(t *testing.T) {
	dir := t.TempDir()
	swnWriteFile(t, dir, "server.properties", "level-name=world\nlevel-type=default\ngenerator-settings=\n")
	a := AuditServerWorldName(dir)
	if a.HasWarnings() {
		t.Fatalf("不应有发现: %v", a.Describe())
	}
}

func TestWorldNameTraversal(t *testing.T) {
	dir := t.TempDir()
	swnWriteFile(t, dir, "server.properties", "level-name=../../outside\n")
	a := AuditServerWorldName(dir)
	if !swnHas(a.Findings, swnReasonName) || !a.Blocking() {
		t.Fatalf("期望路径穿越阻断: %v", a.Describe())
	}
}

func TestWorldNameAbsolute(t *testing.T) {
	dir := t.TempDir()
	swnWriteFile(t, dir, "server.properties", "level-name=/var/lib/world\n")
	a := AuditServerWorldName(dir)
	if !swnHas(a.Findings, swnReasonName) || !a.Blocking() {
		t.Fatalf("期望绝对路径阻断: %v", a.Describe())
	}
}

func TestWorldNameSymlinkDir(t *testing.T) {
	dir := t.TempDir()
	swnWriteFile(t, dir, "server.properties", "level-name=world\n")
	real := t.TempDir()
	if err := os.Symlink(real, filepath.Join(dir, "world")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerWorldName(dir)
	if !swnHas(a.Findings, swnReasonDirLink) || !a.Blocking() {
		t.Fatalf("期望世界目录符号链接阻断: %v", a.Describe())
	}
}

func TestWorldNameUnknownLevelType(t *testing.T) {
	dir := t.TempDir()
	swnWriteFile(t, dir, "server.properties", "level-name=world\nlevel-type=skyblock_nether\n")
	a := AuditServerWorldName(dir)
	if !swnHas(a.Findings, swnReasonLevelType) {
		t.Fatalf("期望未知生成器告警: %v", a.Describe())
	}
}

func TestWorldNameGeneratorSettings(t *testing.T) {
	dir := t.TempDir()
	swnWriteFile(t, dir, "server.properties", "level-name=world\ngenerator-settings={\"layers\":[]}\n")
	a := AuditServerWorldName(dir)
	if !swnHas(a.Findings, swnReasonGenerator) {
		t.Fatalf("期望自定义生成参数告警: %v", a.Describe())
	}
}
