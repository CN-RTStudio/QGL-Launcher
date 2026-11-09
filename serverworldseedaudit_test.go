package main

import (
	"strings"
	"testing"
)


func swsHas(findings []WorldSeedFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestWorldSeedMissing(t *testing.T) {
	a := AuditServerWorldSeed(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少属性文件不应报警: %v", a.Describe())
	}
}

func TestWorldSeedClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "level-seed=\nmax-players=20\nview-distance=10\nsimulation-distance=10\n")
	a := AuditServerWorldSeed(dir)
	if a.HasWarnings() {
		t.Fatalf("不应有发现: %v", a.Describe())
	}
}

func TestWorldSeedExposed(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "level-seed=8642192481\n")
	a := AuditServerWorldSeed(dir)
	if !swsHas(a.Findings, swsReasonSeed) {
		t.Fatalf("期望种子暴露告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("种子暴露不应阻断")
	}
}

func TestWorldSeedControlChars(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "level-seed=abc"+"\x01"+"def\n")
	a := AuditServerWorldSeed(dir)
	if !swsHas(a.Findings, swsReasonSeedBad) || !a.Blocking() {
		t.Fatalf("期望控制字符阻断: %v", a.Describe())
	}
}

func TestWorldSeedPlayersInvalid(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "max-players=2000\n")
	a := AuditServerWorldSeed(dir)
	if !swsHas(a.Findings, swsReasonPlayers) {
		t.Fatalf("期望容量告警: %v", a.Describe())
	}
}

func TestWorldSeedViewDistance(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "view-distance=32\nsimulation-distance=32\n")
	a := AuditServerWorldSeed(dir)
	if !swsHas(a.Findings, swsReasonView) || !swsHas(a.Findings, swsReasonSim) {
		t.Fatalf("期望视距告警: %v", a.Describe())
	}
}

func TestWorldSeedTooLarge(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", strings.Repeat("# padding padding padding padding\n", 9000))
	a := AuditServerWorldSeed(dir)
	if !swsHas(a.Findings, swsReasonTooLarge) || !a.Blocking() {
		t.Fatalf("期望超大阻断: %v", a.Describe())
	}
}
