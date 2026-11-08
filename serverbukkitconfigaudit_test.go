package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sbcWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sbcHas(findings []BukkitFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const sbcGood = `settings:
  allow-end: true
  connection-throttle: 4000
  permissions-file: permissions.yml
  update-folder: update
  shutdown-message: "Server closed"
spawn-limits:
  monsters: 70
chunk-gc:
  period-in-ticks: 600
`

func TestBukkitMissingFile(t *testing.T) {
	a := AuditServerBukkitConfig(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少配置不应报警: %v", a.Describe())
	}
}

func TestBukkitClean(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", sbcGood)
	a := AuditServerBukkitConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("不应有发现: %v", a.Describe())
	}
}

func TestBukkitThrottleDisabled(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "settings:\n  connection-throttle: -1\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonThrottle) || !a.Blocking() {
		t.Fatalf("期望节流关闭阻断: %v", a.Describe())
	}
}

func TestBukkitThrottleInvalid(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "settings:\n  connection-throttle: fast\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonThrottleBad) || !a.Blocking() {
		t.Fatalf("期望非整数阻断: %v", a.Describe())
	}
}

func TestBukkitPermissionsEscape(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "settings:\n  permissions-file: ../../etc/passwd\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonPath) || !a.Blocking() {
		t.Fatalf("期望路径越界阻断: %v", a.Describe())
	}
}

func TestBukkitAbsoluteUpdateFolder(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "settings:\n  update-folder: /tmp/update\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonPath) || !a.Blocking() {
		t.Fatalf("期望绝对路径阻断: %v", a.Describe())
	}
}

func TestBukkitSpawnLimit(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "spawn-limits:\n  monsters: 900\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonSpawn) {
		t.Fatalf("期望刷怪上限告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("刷怪上限不应阻断")
	}
}

func TestBukkitChunkGCDisabled(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "chunk-gc:\n  period-in-ticks: 0\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonChunkGC) {
		t.Fatalf("期望区块回收告警: %v", a.Describe())
	}
}

func TestBukkitEmptyConfig(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", "   \n# only comment\n")
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonEmpty) {
		t.Fatalf("期望空配置告警: %v", a.Describe())
	}
}

func TestBukkitTooLarge(t *testing.T) {
	dir := t.TempDir()
	sbcWriteFile(t, dir, "bukkit.yml", strings.Repeat("# padding padding padding\n", 12000))
	a := AuditServerBukkitConfig(dir)
	if !sbcHas(a.Findings, sbcReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望超大阻断: %v", a.Describe())
	}
}
