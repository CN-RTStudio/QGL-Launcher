package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func spgWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spgHas(findings []PregenFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const spgGoodConfig = "world: world\nradius: 1000\nsilent: true\nsleep: 100\nsave-interval: 30\n"

func TestPregenMissingDir(t *testing.T) {
	a := AuditServerPregen(filepath.Join(t.TempDir(), "absent"))
	if !spgHas(a.Findings, spgReasonMissing) {
		t.Fatalf("期望 missing: %v", a.Describe())
	}
}

func TestPregenGoodConfig(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", spgGoodConfig)
	a := AuditServerPregen(dir)
	if len(a.Findings) != 0 {
		t.Fatalf("合规配置不应有发现: %v", a.Describe())
	}
}

func TestPregenMissingRadius(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", "world: world\nsilent: true\n")
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonNoConfig) || a.Blocking() {
		t.Fatalf("缺 radius 应告警不阻断: %v", a.Describe())
	}
}

func TestPregenZeroRadius(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", strings.Replace(spgGoodConfig, "radius: 1000", "radius: 0", 1))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonRadius) || !a.Blocking() {
		t.Fatalf("radius=0 应阻断: %v", a.Describe())
	}
}

func TestPregenHugeRadius(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", strings.Replace(spgGoodConfig, "radius: 1000", "radius: 10000", 1))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonRadius) || !a.Blocking() {
		t.Fatalf("超上限半径应阻断: %v", a.Describe())
	}
}

func TestPregenWarnRadius(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", strings.Replace(spgGoodConfig, "radius: 1000", "radius: 5000", 1))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonRadiusBig) || a.Blocking() {
		t.Fatalf("过大半径应告警不阻断: %v", a.Describe())
	}
}

func TestPregenWorldTraversal(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", strings.Replace(spgGoodConfig, "world: world", "world: ../../etc/passwd", 1))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonWorld) || !a.Blocking() {
		t.Fatalf("穿越世界名应阻断: %v", a.Describe())
	}
}

func TestPregenWorldsListBad(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", spgGoodConfig+"worlds:\n  - world\n  - ..\\evil\n")
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonWorld) || !a.Blocking() {
		t.Fatalf("列表穿越应阻断: %v", a.Describe())
	}
}

func TestPregenSilentDisabled(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", strings.Replace(spgGoodConfig, "silent: true", "silent: false", 1))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonSilent) || a.Blocking() {
		t.Fatalf("silent=false 应告警: %v", a.Describe())
	}
}

func TestPregenBadSleep(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", strings.Replace(spgGoodConfig, "sleep: 100", "sleep: -20", 1))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonBadValue) || !a.Blocking() {
		t.Fatalf("负 sleep 应阻断: %v", a.Describe())
	}
}

func TestPregenTaskWorldPath(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", spgGoodConfig)
	spgWriteFile(t, dir, "plugins/Chunky/tasks.yml", "worlds:\n  - \"../world_nether\"\n")
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonTasksPath) || !a.Blocking() {
		t.Fatalf("任务世界路径应阻断: %v", a.Describe())
	}
}

func TestPregenSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "chunky.yml")
	if err := os.WriteFile(outside, []byte(spgGoodConfig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "plugins", "Chunky"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "plugins", "Chunky", "config.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonSymlink) || !a.Blocking() {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}

func TestPregenOversize(t *testing.T) {
	dir := t.TempDir()
	spgWriteFile(t, dir, "plugins/Chunky/config.yml", spgGoodConfig+strings.Repeat("# pad\n", 60000))
	a := AuditServerPregen(dir)
	if !spgHas(a.Findings, spgReasonTooLarge) || !a.Blocking() {
		t.Fatalf("超大配置应阻断: %v", a.Describe())
	}
}
