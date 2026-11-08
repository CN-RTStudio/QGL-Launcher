package main

import (
	"os"
	"path/filepath"
	"testing"
)

func srqWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func srqHas(a *ResourceQuotaAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestResourceQuotaClean(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "max-players=20\nmax-entity-collisions=8\nmax-world-size=29999984\nspawn-protection=16\nplayer-idle-timeout=5\nnetwork-compression-threshold=256\npause-when-empty-seconds=60\n")
	a := AuditServerResourceQuota(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}

func TestResourceQuotaMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestResourceQuotaMaxPlayersInvalid(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "max-players=500\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqMaxPlayers) {
		t.Fatalf("玩家上限越界应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("玩家上限越界应阻断: %v", a.Describe())
	}
}

func TestResourceQuotaMaxPlayersGarbage(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "max-players=lots\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqMaxPlayers) {
		t.Fatalf("非整数玩家上限应记录: %v", a.Describe())
	}
}

func TestResourceQuotaCollisionsExcessive(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "max-entity-collisions=80\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqCollisions) {
		t.Fatalf("实体碰撞过高应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("实体碰撞过高不应阻断: %v", a.Describe())
	}
}

func TestResourceQuotaWorldSizeInvalid(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "max-world-size=10\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqWorldSize) {
		t.Fatalf("世界尺寸越界应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("世界尺寸越界应阻断: %v", a.Describe())
	}
}

func TestResourceQuotaSpawnProtectionExcessive(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "spawn-protection=64\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqSpawnGuard) {
		t.Fatalf("出生点保护过大应提示: %v", a.Describe())
	}
}

func TestResourceQuotaIdleTimeoutOutOfRange(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "player-idle-timeout=2880\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqIdleBound) {
		t.Fatalf("休眠超时应提示: %v", a.Describe())
	}
}

func TestResourceQuotaCompressionIneffective(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "network-compression-threshold=4096\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqCompressBig) {
		t.Fatalf("压缩阈值过高应提示: %v", a.Describe())
	}
}

func TestResourceQuotaPauseIdleExcessive(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "pause-when-empty-seconds=7200\n")
	a := AuditServerResourceQuota(dir)
	if !srqHas(a, srqPauseIdle) {
		t.Fatalf("空服暂停过久应提示: %v", a.Describe())
	}
}

func TestResourceQuotaBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "\ufeffmax-players=\"20\"\nspawn-protection=\"16\"\n")
	a := AuditServerResourceQuota(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}

func TestResourceQuotaMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	srqWrite(t, dir, "max-players=500\nmax-world-size=10\nspawn-protection=64\n")
	a := AuditServerResourceQuota(dir)
	if len(a.Findings) != 3 {
		t.Fatalf("应有 3 条发现: %v", a.Describe())
	}
}
