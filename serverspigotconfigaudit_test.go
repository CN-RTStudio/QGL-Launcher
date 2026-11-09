package main

import (
	"os"
	"path/filepath"
	"testing"
)


func sptSrvHas(findings []SpigotFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestSpigotMissingFile(t *testing.T) {
	a := AuditServerSpigotConfig(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少 spigot.yml 不应报警: %v", a.Describe())
	}
}

func TestSpigotClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  bungeecord: false\n  timeout-time: 60\nworld-settings:\n  default:\n    max-tnt-per-tick: 100\n    entity-activation-range:\n      animals: 32\n")
	a := AuditServerSpigotConfig(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合法配置不应报警: %v", a.Describe())
	}
}

func TestSpigotBungeeCord(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n")
	a := AuditServerSpigotConfig(dir)
	if !a.Blocking() || !sptSrvHas(a.Findings, sptReasonBungee) {
		t.Fatalf("BungeeCord 模式应阻断: %v", a.Describe())
	}
}

func TestSpigotRestartScript(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  restart-script: /tmp/evil.sh\n")
	a := AuditServerSpigotConfig(dir)
	if !a.Blocking() || !sptSrvHas(a.Findings, sptReasonScript) {
		t.Fatalf("自定义重启脚本应阻断: %v", a.Describe())
	}
}

func TestSpigotMessageControlChars(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "spigot.yml", "messages:\n  whitelist: '拒绝\u0000'\n")
	a := AuditServerSpigotConfig(dir)
	if !a.Blocking() || !sptSrvHas(a.Findings, sptReasonMsg) {
		t.Fatalf("提示语控制字符应阻断: %v", a.Describe())
	}
}

func TestSpigotTimeoutAndTNT(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  timeout-time: 600\nworld-settings:\n  default:\n    max-tnt-per-tick: 500\n")
	a := AuditServerSpigotConfig(dir)
	if a.Blocking() || !sptSrvHas(a.Findings, sptReasonTimeout) || !sptSrvHas(a.Findings, sptReasonTNT) {
		t.Fatalf("超时与 TNT 预算应告警: %v", a.Describe())
	}
}

func TestSpigotSymlink(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "real.yml", "settings:\n")
	if err := os.Symlink(filepath.Join(dir, "real.yml"), filepath.Join(dir, "spigot.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerSpigotConfig(dir)
	if !a.Blocking() || !sptSrvHas(a.Findings, sptReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
