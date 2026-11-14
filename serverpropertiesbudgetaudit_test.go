package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPropertiesBudgetMissing(t *testing.T) {
	a := AuditServerPropertiesBudget(t.TempDir())
	if a.Blocking() {
		t.Fatalf("无配置不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonMissing) {
		t.Fatalf("应报告缺少配置: %s", a.Describe())
	}
}

func TestPropertiesBudgetDuplicateKeys(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "online-mode=true\nmotd=a\nMOTD=b\n")
	a := AuditServerPropertiesBudget(dir)
	if a.Blocking() {
		t.Fatalf("重复键不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonDupKey) {
		t.Fatalf("应报告重复键: %s", a.Describe())
	}
	if a.Keys != 2 {
		t.Fatalf("键数应为 2, 实际 %d", a.Keys)
	}
}

func TestPropertiesBudgetViewDistance(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "view-distance=32\nsimulation-distance=48\n")
	a := AuditServerPropertiesBudget(dir)
	if a.Blocking() {
		t.Fatalf("视距过大不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonViewLarge) {
		t.Fatalf("应报告视距过大: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonSimDistance) {
		t.Fatalf("应报告模拟距离超过视距: %s", a.Describe())
	}
}

func TestPropertiesBudgetViewSmall(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "view-distance=1\n")
	a := AuditServerPropertiesBudget(dir)
	if !auditHasReason(a, sprReasonViewSmall) {
		t.Fatalf("应报告视距过小: %s", a.Describe())
	}
}

func TestPropertiesBudgetCompression(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "network-compression-threshold=4096\n")
	a := AuditServerPropertiesBudget(dir)
	if a.Blocking() {
		t.Fatalf("压缩阈值越界不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonCompression) {
		t.Fatalf("应报告压缩阈值越界: %s", a.Describe())
	}
}

func TestPropertiesBudgetWatchdog(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "max-tick-time=-1\n")
	a := AuditServerPropertiesBudget(dir)
	if !a.Blocking() {
		t.Fatalf("关闭看门狗应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonWatchdog) {
		t.Fatalf("应报告看门狗关闭: %s", a.Describe())
	}
}

func TestPropertiesBudgetPortConflict(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "server-port=25565\nquery.port=25565\n")
	a := AuditServerPropertiesBudget(dir)
	if a.Blocking() {
		t.Fatalf("端口冲突不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonPortClash) {
		t.Fatalf("应报告端口冲突: %s", a.Describe())
	}
}

func TestPropertiesBudgetLevelTraversal(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "level-name=../../etc\n")
	a := AuditServerPropertiesBudget(dir)
	if !a.Blocking() {
		t.Fatalf("关卡路径穿越应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonLevelName) {
		t.Fatalf("应报告路径穿越: %s", a.Describe())
	}
}

func TestPropertiesBudgetLevelControlChars(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "level-name=world\u0007\n")
	a := AuditServerPropertiesBudget(dir)
	if !a.Blocking() {
		t.Fatalf("关卡名控制字符应阻断: %s", a.Describe())
	}
}

func TestPropertiesBudgetResourcePack(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "resource-pack=http://example.com/pack.zip\nresource-pack-sha1=\n")
	a := AuditServerPropertiesBudget(dir)
	if a.Blocking() {
		t.Fatalf("资源包明文不应阻断: %s", a.Describe())
	}
	count := 0
	for _, f := range a.Findings {
		if f.Reason == sprReasonPackURL {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("应报告两项资源包问题, 实际 %d: %s", count, a.Describe())
	}
}

func TestPropertiesBudgetOversized(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "server.properties", "motd="+strings.Repeat("x", sprMaxProps+8)+"\n")
	a := AuditServerPropertiesBudget(dir)
	if !a.Blocking() {
		t.Fatalf("超大配置应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, sprReasonTooLarge) {
		t.Fatalf("应报告体积超限: %s", a.Describe())
	}
}

func TestPropertiesBudgetSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(target, []byte("online-mode=true\n"), 0o644); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditServerPropertiesBudget(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接应阻断: %s", a.Describe())
	}
}

func TestPropertiesBudgetClean(t *testing.T) {
	dir := t.TempDir()
	body := "server-port=25565\nquery.port=25566\nmax-tick-time=60000\nview-distance=10\nsimulation-distance=8\nnetwork-compression-threshold=256\nlevel-name=world\nresource-pack=https://example.com/pack.zip\n"
	auditWriteFileBody(t, dir, "server.properties", body)
	a := AuditServerPropertiesBudget(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合规配置不应产生问题: %s", a.Describe())
	}
	if a.Keys != 8 {
		t.Fatalf("键数应为 8, 实际 %d", a.Keys)
	}
}
