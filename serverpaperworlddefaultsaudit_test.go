package main

import (
	"os"
	"path/filepath"
	"testing"
)

func swdWrite(t *testing.T, dir, content string) {
	t.Helper()
	path := filepath.Join(dir, "config", "paper-world-defaults.yml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func swdHas(findings []PaperWorldFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPaperWorldClean(t *testing.T) {
	dir := t.TempDir()
	swdWrite(t, dir, "anticheat:\n  anti-xray:\n    enabled: true\ncollisions:\n  max-entity-collisions: 8\nchunks:\n  max-auto-save-chunks-per-tick: 24\n  prevent-moving-into-unloaded-chunks: true\ndespawn-ranges:\n  monster:\n    hard: 128\n")
	if a := AuditServerPaperWorldDefaults(dir); a.HasWarnings() {
		t.Fatalf("合法配置不应报警: %v", a.Describe())
	}
}

func TestPaperWorldXray(t *testing.T) {
	dir := t.TempDir()
	swdWrite(t, dir, "anticheat:\n  anti-xray:\n    enabled: false\n")
	a := AuditServerPaperWorldDefaults(dir)
	if !swdHas(a.Findings, swdReasonXray) {
		t.Fatalf("关闭反透视应报警: %v", a.Describe())
	}
}

func TestPaperWorldAutoSave(t *testing.T) {
	dir := t.TempDir()
	swdWrite(t, dir, "chunks:\n  max-auto-save-chunks-per-tick: 0\n")
	a := AuditServerPaperWorldDefaults(dir)
	if !a.Blocking() || !swdHas(a.Findings, swdReasonSave) {
		t.Fatalf("自动保存为 0 应阻断: %v", a.Describe())
	}
}

func TestPaperWorldDespawn(t *testing.T) {
	dir := t.TempDir()
	swdWrite(t, dir, "despawn-ranges:\n  monster:\n    hard: 300\n")
	a := AuditServerPaperWorldDefaults(dir)
	if !swdHas(a.Findings, swdReasonRange) {
		t.Fatalf("despawn 范围异常应报警: %v", a.Describe())
	}
}

func TestPaperWorldMissing(t *testing.T) {
	if a := AuditServerPaperWorldDefaults(t.TempDir()); a.Blocking() {
		t.Fatalf("缺少文件不应阻断: %v", a.Describe())
	}
}
