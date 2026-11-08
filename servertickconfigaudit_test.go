package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tkWrite(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

func tkHas(a TickConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAuditServerTickConfigHealthy(t *testing.T) {
	dir := tkWrite(t, strings.Join([]string{
		"level-name=world",
		"max-tick-time=60000",
		"sync-chunk-writes=true",
		"max-players=20",
		"network-compression-threshold=256",
		"view-distance=10",
		"simulation-distance=10",
		"entity-broadcast-range-percentage=100",
		"max-entity-collisions=8",
		"player-idle-timeout=15",
		"spawn-protection=16",
		"enable-status=true",
	}, "\n"))
	audit := AuditServerTickConfig(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("健康参数被误报: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigWatchdog(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nmax-tick-time=-1\n")
	audit := AuditServerTickConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("关闭看门狗应阻断: %s", audit.Describe())
	}
	if !tkHas(audit, tkReasonWatchdogOff) {
		t.Fatalf("缺少 watchdog 原因: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigShortTick(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nmax-tick-time=200\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonTickBudget) {
		t.Fatalf("过短 tick 预算未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("过短 tick 预算只应告警")
	}
}

func TestAuditServerTickConfigUnsafeSave(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nsync-chunk-writes=false\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonUnsafeSave) {
		t.Fatalf("异步写盘未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigPlayerLimit(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nmax-players=0\n")
	audit := AuditServerTickConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("零玩家上限应阻断: %s", audit.Describe())
	}
	dir = tkWrite(t, "level-name=world\nmax-players=500\n")
	audit = AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonPlayerLimit) || audit.Blocking() {
		t.Fatalf("超大玩家上限判定错误: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigCompression(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nnetwork-compression-threshold=-1\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonCompression) {
		t.Fatalf("关闭压缩未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigViewDistance(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nview-distance=32\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonViewDistance) {
		t.Fatalf("超远视距未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigSimulation(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nsimulation-distance=0\n")
	audit := AuditServerTickConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("零模拟距离应阻断: %s", audit.Describe())
	}
	dir = tkWrite(t, "level-name=world\nview-distance=6\nsimulation-distance=10\n")
	audit = AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonSimulation) {
		t.Fatalf("模拟距离大于视距未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigBroadcast(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nentity-broadcast-range-percentage=400\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonBroadcast) {
		t.Fatalf("广播范围越界未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigCollisions(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nmax-entity-collisions=32\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonCollisions) {
		t.Fatalf("实体挤压上限过高未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigIdleAndSpawn(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nplayer-idle-timeout=0\nspawn-protection=0\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonIdleTimeout) {
		t.Fatalf("挂机踢出关闭未检出: %s", audit.Describe())
	}
	if !tkHas(audit, tkReasonSpawnProtection) {
		t.Fatalf("出生点保护关闭未检出: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigRequiredResourcePack(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nrequire-resource-pack=true\n")
	audit := AuditServerTickConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("强制资源包无地址应阻断: %s", audit.Describe())
	}
	if !tkHas(audit, tkReasonResourcePack) {
		t.Fatalf("缺少 resource-pack 原因: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigLevelName(t *testing.T) {
	for _, name := range []string{"../escape", "a/b", "..", ""} {
		dir := tkWrite(t, "level-name="+name+"\n")
		audit := AuditServerTickConfig(dir)
		if !audit.Blocking() {
			t.Fatalf("level-name=%q 应阻断: %s", name, audit.Describe())
		}
		if !tkHas(audit, tkReasonLevelName) {
			t.Fatalf("level-name=%q 缺少原因", name)
		}
	}
	if tkLevelNameSafe("world_nether") != true {
		t.Fatalf("正常世界名被判非法")
	}
}

func TestAuditServerTickConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(target, []byte("level-name=world\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "server.properties")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	audit := AuditServerTickConfig(dir)
	if !audit.Blocking() || !tkHas(audit, tkReasonSymlink) {
		t.Fatalf("符号链接未阻断: %s", audit.Describe())
	}
}

func TestAuditServerTickConfigStatus(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nenable-status=false\n")
	audit := AuditServerTickConfig(dir)
	if !tkHas(audit, tkReasonStatusOff) {
		t.Fatalf("隐藏状态未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("隐藏状态只应告警")
	}
}

func TestAuditServerTickConfigDescribe(t *testing.T) {
	dir := tkWrite(t, "level-name=world\nmax-tick-time=-1\n")
	audit := AuditServerTickConfig(dir)
	if !strings.Contains(audit.Describe(), tkReasonWatchdogOff) {
		t.Fatalf("描述缺少原因: %s", audit.Describe())
	}
	if !strings.Contains(audit.Describe(), "server.properties") {
		t.Fatalf("描述缺少来源: %s", audit.Describe())
	}
}
