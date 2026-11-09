package main

import (
	"testing"
)


func shcHas(a *HardcoreAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestHardcoreClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "hardcore=true\ndifficulty=hard\npvp=true\ngamemode=survival\nforce-gamemode=true\nspawn-protection=16\n")
	if a := AuditServerHardcore(dir); a.HasWarnings() {
		t.Fatalf("硬核配置一致不应报警: %v", a.Describe())
	}
}

func TestHardcoreDifficultyMismatch(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "hardcore=true\ndifficulty=normal\n")
	a := AuditServerHardcore(dir)
	if !a.Blocking() || !shcHas(a, shcReasonHard) {
		t.Fatalf("难度不一致应阻断: %v", a.Describe())
	}
}

func TestHardcorePVPOff(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "hardcore=true\ndifficulty=hard\npvp=false\n")
	a := AuditServerHardcore(dir)
	if !shcHas(a, shcReasonPVP) {
		t.Fatalf("硬核关 PVP 应提示: %v", a.Describe())
	}
}

func TestHardcoreInvalidGamemode(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "gamemode=godmode\n")
	a := AuditServerHardcore(dir)
	if !a.Blocking() || !shcHas(a, shcReasonGamemod) {
		t.Fatalf("非法游戏模式应阻断: %v", a.Describe())
	}
}

func TestHardcoreInvalidDifficulty(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "difficulty=nightmare\n")
	a := AuditServerHardcore(dir)
	if !a.Blocking() || !shcHas(a, shcReasonDiff) {
		t.Fatalf("非法难度应阻断: %v", a.Describe())
	}
}

func TestHardcoreSpawnProtectionOff(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "spawn-protection=0\n")
	a := AuditServerHardcore(dir)
	if !shcHas(a, shcReasonSpawn) {
		t.Fatalf("出生点保护关闭应提示: %v", a.Describe())
	}
}
