package main

import (
	"os"
	"path/filepath"
	"testing"
)


func cfdHasReason(a *ConnectionFloodAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestConnectionFloodMissingDir(t *testing.T) {
	a := AuditServerConnectionFlood("")
	if a.Blocking() {
		t.Fatalf("空目录不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdReasonMissing) {
		t.Fatalf("应报告缺少目录: %s", a.Describe())
	}
}

func TestConnectionFloodEmptyServer(t *testing.T) {
	a := AuditServerConnectionFlood(t.TempDir())
	if a.Blocking() {
		t.Fatalf("空服务器不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdReasonMissing) {
		t.Fatalf("应报告缺少配置: %s", a.Describe())
	}
}

func TestConnectionFloodThrottleDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "bukkit.yml", "settings:\n  connection-throttle: -1\n")
	a := AuditServerConnectionFlood(dir)
	if !a.Blocking() {
		t.Fatalf("关闭节流应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdThrottleOff) {
		t.Fatalf("应报告节流关闭: %s", a.Describe())
	}
}

func TestConnectionFloodThrottleZero(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "bukkit.yml", "settings:\n  connection-throttle: 0\n")
	a := AuditServerConnectionFlood(dir)
	if !a.Blocking() {
		t.Fatalf("零节流应阻断: %s", a.Describe())
	}
}

func TestConnectionFloodThrottleLoose(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "bukkit.yml", "settings:\n  connection-throttle: 60000\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() {
		t.Fatalf("宽松节流不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdThrottleLoose) {
		t.Fatalf("应告警节流宽松: %s", a.Describe())
	}
}

func TestConnectionFloodBadThrottle(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "bukkit.yml", "settings:\n  connection-throttle: fast\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() {
		t.Fatalf("非法节流不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdReasonBadValue) {
		t.Fatalf("应报告非法取值: %s", a.Describe())
	}
}

func TestConnectionFloodSlowTimeout(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "spigot.yml", "settings:\n  timeout-time: 1800\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() {
		t.Fatalf("超时过大不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdTimeoutLoose) {
		t.Fatalf("应告警超时过长: %s", a.Describe())
	}
}

func TestConnectionFloodJoinBurst(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "misc:\n  max-joins-per-tick: 64\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() {
		t.Fatalf("登录洪峰不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdJoinBurst) {
		t.Fatalf("应告警登录洪峰: %s", a.Describe())
	}
}

func TestConnectionFloodRateLimitDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "rate-limit=0\nplayer-idle-timeout=0\nmax-players=500\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() {
		t.Fatalf("属性告警不应阻断: %s", a.Describe())
	}
	for _, reason := range []string{cfdRateLimitOff, cfdTimeoutLoose, cfdPlayersBulk} {
		if !cfdHasReason(a, reason) {
			t.Fatalf("缺少 %s: %s", reason, a.Describe())
		}
	}
}

func TestConnectionFloodThrottleConflict(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "bukkit.yml", "settings:\n  connection-throttle: 4000\n")
	auditWriteFileBody(t, dir, "spigot.yml", "settings:\n  connection-throttle: 1000\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() {
		t.Fatalf("节流不一致不应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdConflict) {
		t.Fatalf("应报告节流不一致: %s", a.Describe())
	}
}

func TestConnectionFloodSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yml")
	if err := os.WriteFile(target, []byte("settings:\n  connection-throttle: 4000\n"), 0o644); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "bukkit.yml")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditServerConnectionFlood(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接应阻断: %s", a.Describe())
	}
	if !cfdHasReason(a, cfdReasonSymlink) {
		t.Fatalf("应报告符号链接: %s", a.Describe())
	}
}

func TestConnectionFloodCleanConfig(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "bukkit.yml", "settings:\n  connection-throttle: 4000\n")
	auditWriteFileBody(t, dir, "spigot.yml", "settings:\n  connection-throttle: 4000\n  timeout-time: 180\n  player-shuffle: 30\n")
	auditWriteFileBody(t, dir, "server.properties", "max-players=20\nrate-limit=10\nplayer-idle-timeout=15\n")
	a := AuditServerConnectionFlood(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合规配置不应产生问题: %s", a.Describe())
	}
}
