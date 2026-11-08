package main

import (
	"os"
	"path/filepath"
	"testing"
)

func swpWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func swpHas(a *WorldConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestWorldConfigClean(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "max-world-size=29999984\nspawn-protection=16\nallow-flight=false\nview-distance=10\nsimulation-distance=10\nmax-tick-time=60000\nentity-broadcast-range-percentage=100\n")
	a := AuditServerWorldConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
}

func TestWorldConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestWorldConfigEmptyDir(t *testing.T) {
	a := AuditServerWorldConfig("")
	if !swpHas(a, swpMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestWorldConfigMaxWorldSizeInvalid(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "max-world-size=0\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpWorldSize) {
		t.Fatalf("世界尺寸越界应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("世界尺寸越界应阻断: %v", a.Describe())
	}
}

func TestWorldConfigMaxWorldSizeText(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "max-world-size=big\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpWorldSize) {
		t.Fatalf("非整数尺寸应阻断: %v", a.Describe())
	}
}

func TestWorldConfigSpawnProtectionZero(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "spawn-protection=0\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpSpawn) {
		t.Fatalf("出生点无保护应提示: %v", a.Describe())
	}
}

func TestWorldConfigSpawnProtectionHuge(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "spawn-protection=20000\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpSpawn) {
		t.Fatalf("保护半径过大应提示: %v", a.Describe())
	}
}

func TestWorldConfigAllowFlight(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "allow-flight=true\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpFlight) {
		t.Fatalf("允许飞行应提示: %v", a.Describe())
	}
}

func TestWorldConfigViewDistanceInvalid(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "view-distance=64\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpViewDist) {
		t.Fatalf("视距越界应提示: %v", a.Describe())
	}
}

func TestWorldConfigSimDistanceInvalid(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "simulation-distance=1\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpSimDist) {
		t.Fatalf("模拟距离越界应提示: %v", a.Describe())
	}
}

func TestWorldConfigTickTimeDisabled(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "max-tick-time=-1\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpTickTime) {
		t.Fatalf("关闭看门狗应提示: %v", a.Describe())
	}
}

func TestWorldConfigBroadcastRangeInvalid(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "entity-broadcast-range-percentage=5\n")
	a := AuditServerWorldConfig(dir)
	if !swpHas(a, swpBroadcast) {
		t.Fatalf("实体广播范围越界应阻断: %v", a.Describe())
	}
}

func TestWorldConfigBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "\ufeffmax-world-size=\"29999984\"\nview-distance=\"10\"\n")
	a := AuditServerWorldConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}

func TestWorldConfigMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	swpWrite(t, dir, "max-world-size=0\nspawn-protection=0\nallow-flight=true\nview-distance=64\n")
	a := AuditServerWorldConfig(dir)
	if len(a.Findings) != 4 {
		t.Fatalf("应有 4 条发现: %v", a.Describe())
	}
}
