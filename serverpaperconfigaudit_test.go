package main

import (
	"os"
	"path/filepath"
	"testing"
)

func pacPaperWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func pacPaperHas(findings []PaperFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPaperMissingFile(t *testing.T) {
	a := AuditServerPaperConfig(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("缺少 paper-global.yml 不应报警: %v", a.Describe())
	}
}

func TestPaperVelocityGoodSecret(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'B3cr9xQm2Lp7vT0a'\n    online-mode: true\n")
	a := AuditServerPaperConfig(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合法 Velocity 配置不应报警: %v", a.Describe())
	}
}

func TestPaperVelocityWeakSecret(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'changeme'\n")
	a := AuditServerPaperConfig(dir)
	if !a.Blocking() || !pacPaperHas(a.Findings, pacReasonSecret) {
		t.Fatalf("占位密钥应阻断: %v", a.Describe())
	}
}

func TestPaperVelocityEmptySecret(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: ''\n")
	a := AuditServerPaperConfig(dir)
	if !a.Blocking() || !pacPaperHas(a.Findings, pacReasonSecret) {
		t.Fatalf("空密钥应阻断: %v", a.Describe())
	}
}

func TestPaperOfflineMode(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/paper-global.yml", "proxies:\n  bungee-cord:\n    online-mode: false\n")
	a := AuditServerPaperConfig(dir)
	if a.Blocking() || !pacPaperHas(a.Findings, pacReasonOffline) {
		t.Fatalf("离线转发模式应告警: %v", a.Describe())
	}
}

func TestPaperKickMessage(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/paper-global.yml", "messages:\n  kick: '已踢出\u0007'\n")
	a := AuditServerPaperConfig(dir)
	if !a.Blocking() || !pacPaperHas(a.Findings, pacReasonKick) {
		t.Fatalf("踢出提示语控制字符应阻断: %v", a.Describe())
	}
}

func TestPaperBudgets(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/paper-global.yml", "chunk-loading:\n  max-concurrent-sends: 500\nmisc:\n  max-joins-per-tick: 200\n")
	a := AuditServerPaperConfig(dir)
	if a.Blocking() || !pacPaperHas(a.Findings, pacReasonSends) || !pacPaperHas(a.Findings, pacReasonJoins) {
		t.Fatalf("预算超限应告警: %v", a.Describe())
	}
}

func TestPaperSymlink(t *testing.T) {
	dir := t.TempDir()
	pacPaperWrite(t, dir, "config/real.yml", "proxies:\n")
	if err := os.Symlink(filepath.Join(dir, "config/real.yml"), filepath.Join(dir, "config/paper-global.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerPaperConfig(dir)
	if !a.Blocking() || !pacPaperHas(a.Findings, pacReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
