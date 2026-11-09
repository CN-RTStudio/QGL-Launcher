package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sytWriteProps(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write props: %v", err)
	}
}

func sytHas(a *WorldSymlinkAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func sytCount(a *WorldSymlinkAudit, reason string) int {
	count := 0
	for _, f := range a.Findings {
		if f.Reason == reason {
			count++
		}
	}
	return count
}

func TestWorldSymlinkClean(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=world\n")
	world := filepath.Join(dir, "world")
	if err := os.MkdirAll(filepath.Join(world, "region"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(world, "level.dat"), []byte("data"), 0o644); err != nil {
		t.Fatalf("write level.dat: %v", err)
	}
	a := AuditServerWorldSymlinks(dir)
	if a.HasWarnings() {
		t.Fatalf("干净存档不应报警: %v", a.Describe())
	}
	if a.Entries < 2 {
		t.Fatalf("应扫描到存档条目: %d", a.Entries)
	}
}

func TestWorldSymlinkMissing(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=world\n")
	a := AuditServerWorldSymlinks(dir)
	if !sytHas(a, sytMissing) {
		t.Fatalf("缺少世界目录应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("目录缺失不应阻断启动: %v", a.Describe())
	}
}

func TestWorldSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=world\n")
	world := filepath.Join(dir, "world")
	if err := os.MkdirAll(world, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	outside := filepath.Join(dir, "secrets")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "token.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(world, "escape")); err != nil {
		t.Skipf("平台不支持创建符号链接: %v", err)
	}
	a := AuditServerWorldSymlinks(dir)
	if !sytHas(a, sytEscape) || !a.Blocking() {
		t.Fatalf("越界符号链接应阻断: %v", a.Describe())
	}
}

func TestWorldSymlinkInnerLink(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=world\n")
	world := filepath.Join(dir, "world")
	if err := os.MkdirAll(world, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(world, "level.dat")
	if err := os.WriteFile(target, []byte("d"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(world, "alias.dat")); err != nil {
		t.Skipf("平台不支持创建符号链接: %v", err)
	}
	a := AuditServerWorldSymlinks(dir)
	if sytCount(a, sytLink) != 1 {
		t.Fatalf("内部链接应记一次告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("内部链接不应阻断: %v", a.Describe())
	}
}

func TestWorldSymlinkUnsafeLevelName(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=../escape\n")
	a := AuditServerWorldSymlinks(dir)
	if a.WorldDir != filepath.Join(dir, "world") {
		t.Fatalf("非法 level-name 应回落到 world: %s", a.WorldDir)
	}
	if !sytHas(a, sytMissing) {
		t.Fatalf("回落目录不存在应告警: %v", a.Describe())
	}
}

func TestWorldSymlinkLockFile(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=world\n")
	world := filepath.Join(dir, "world")
	if err := os.MkdirAll(world, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(world, "session.lock"), []byte{0}, 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	a := AuditServerWorldSymlinks(dir)
	if !sytHas(a, sytLockFile) {
		t.Fatalf("残留 session.lock 应告警: %v", a.Describe())
	}
}

func TestWorldSymlinkEmptyServerDir(t *testing.T) {
	a := AuditServerWorldSymlinks("")
	if !a.Blocking() || !sytHas(a, sytMissing) {
		t.Fatalf("空目录参数应阻断: %v", a.Describe())
	}
}

func TestWorldSymlinkDescribeStable(t *testing.T) {
	dir := t.TempDir()
	sytWriteProps(t, dir, "level-name=world\n")
	a := AuditServerWorldSymlinks(dir)
	first := a.Describe()
	second := a.Describe()
	if first != second {
		t.Fatalf("描述文本应稳定: %q vs %q", first, second)
	}
}
