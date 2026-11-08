package main

import (
	"os"
	"path/filepath"
	"testing"
)

func slgWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func slgHas(a *LagGuardAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestLagGuardClean(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "view-distance=10\nsimulation-distance=10\nmax-chained-neighbor-updates=100000\nsync-chunk-writes=true\nmax-tick-time=60000\nentity-broadcast-range-percentage=100\n")
	a := AuditServerLagGuard(dir)
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

func TestLagGuardMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestLagGuardViewDistanceWarn(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "view-distance=12\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgViewDist) {
		t.Fatalf("视距偏高应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("视距偏高不应阻断: %v", a.Describe())
	}
}

func TestLagGuardViewDistanceBlocking(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "view-distance=40\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgViewDist) {
		t.Fatalf("视距越界应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("视距越界应阻断: %v", a.Describe())
	}
}

func TestLagGuardViewDistanceGarbage(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "view-distance=far\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgViewDist) {
		t.Fatalf("非整数视距应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非整数视距应阻断: %v", a.Describe())
	}
}

func TestLagGuardSimulationDistanceWarn(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "simulation-distance=15\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgSimDist) {
		t.Fatalf("模拟距离偏高应提示: %v", a.Describe())
	}
}

func TestLagGuardChainUnbounded(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "max-chained-neighbor-updates=-1\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgChain) {
		t.Fatalf("链式更新无上限应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("链式更新无上限应阻断: %v", a.Describe())
	}
}

func TestLagGuardSyncWritesOff(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "sync-chunk-writes=false\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgSyncWrites) {
		t.Fatalf("关闭同步写入应提示: %v", a.Describe())
	}
}

func TestLagGuardWatchdogOff(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "max-tick-time=-1\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgTickTime) {
		t.Fatalf("看门狗关闭应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("看门狗关闭不应阻断: %v", a.Describe())
	}
}

func TestLagGuardWatchdogInvalid(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "max-tick-time=0\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgTickTime) {
		t.Fatalf("非法看门狗取值应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非法看门狗取值应阻断: %v", a.Describe())
	}
}

func TestLagGuardBroadcastExcessive(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "entity-broadcast-range-percentage=150\n")
	a := AuditServerLagGuard(dir)
	if !slgHas(a, slgBroadcast) {
		t.Fatalf("实体广播范围过大应提示: %v", a.Describe())
	}
}

func TestLagGuardMultipleFindingsSorted(t *testing.T) {
	dir := t.TempDir()
	slgWrite(t, dir, "view-distance=12\nsimulation-distance=12\nsync-chunk-writes=false\n")
	a := AuditServerLagGuard(dir)
	if len(a.Findings) != 3 {
		t.Fatalf("应有 3 条发现: %v", a.Describe())
	}
	if !a.HasWarnings() {
		t.Fatalf("应有告警: %v", a.Describe())
	}
}
