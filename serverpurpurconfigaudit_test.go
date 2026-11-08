package main

import (
	"os"
	"path/filepath"
	"testing"
)

func spqWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "purpur.yml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spqHas(findings []PurpurFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPurpurClean(t *testing.T) {
	dir := t.TempDir()
	spqWrite(t, dir, "settings:\n  messages:\n    kick: \"Server closed\"\n  use-alternative-luck-formula: false\nworld-settings:\n  default:\n    player:\n      teleport-invulnerability: 5\n")
	if a := AuditServerPurpurConfig(dir); a.HasWarnings() {
		t.Fatalf("合法配置不应报警: %v", a.Describe())
	}
}

func TestPurpurMessageControl(t *testing.T) {
	dir := t.TempDir()
	spqWrite(t, dir, "settings:\n  messages:\n    kick: \"bad\x07text\"\n")
	a := AuditServerPurpurConfig(dir)
	if !a.Blocking() || !spqHas(a.Findings, spqReasonMsg) {
		t.Fatalf("消息控制字符应阻断: %v", a.Describe())
	}
}

func TestPurpurPermissive(t *testing.T) {
	dir := t.TempDir()
	spqWrite(t, dir, "settings:\n  blocks:\n    allow-player-inventory-lookup: true\n")
	a := AuditServerPurpurConfig(dir)
	if !spqHas(a.Findings, spqReasonAllow) {
		t.Fatalf("宽松开关应报警: %v", a.Describe())
	}
}

func TestPurpurJoinLimit(t *testing.T) {
	dir := t.TempDir()
	spqWrite(t, dir, "world-settings:\n  default:\n    join:\n      limit: 0\n")
	a := AuditServerPurpurConfig(dir)
	if !spqHas(a.Findings, spqReasonJoin) {
		t.Fatalf("加入上限为 0 应报警: %v", a.Describe())
	}
}
