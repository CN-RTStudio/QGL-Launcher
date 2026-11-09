package main

import (
	"os"
	"path/filepath"
	"testing"
)


func pklHasReason(a *PacketLimiterAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPacketLimiterMissingConfig(t *testing.T) {
	a := AuditServerPacketLimiter(t.TempDir())
	if a.Blocking() {
		t.Fatalf("无配置不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonMissing) {
		t.Fatalf("应报告缺少配置: %s", a.Describe())
	}
}

func TestPacketLimiterDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "packet-limiter:\n  enabled: false\n")
	a := AuditServerPacketLimiter(dir)
	if !a.Blocking() {
		t.Fatalf("关闭限速应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonLimiterOff) {
		t.Fatalf("应报告限速关闭: %s", a.Describe())
	}
}

func TestPacketLimiterLooseRate(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "packet-limiter:\n  enabled: true\n  all-packets:\n    max-packet-rate: 5000\n    interval: 7.0\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("宽松限速不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonLimiterLoose) {
		t.Fatalf("应告警限速宽松: %s", a.Describe())
	}
	if a.Limits == 0 {
		t.Fatalf("应统计到限速项: %s", a.Describe())
	}
}

func TestPacketLimiterBadInterval(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "packet-limiter:\n  enabled: true\n  all-packets:\n    max-packet-rate: 300\n    interval: 0\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("间隔非法不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonBadValue) {
		t.Fatalf("应报告非法间隔: %s", a.Describe())
	}
}

func TestPacketLimiterKickMessage(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "packet-limiter:\n  enabled: true\n  kick-message: \"stop\u0007now\"\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("踢出消息不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonKickMessage) {
		t.Fatalf("应报告控制字符: %s", a.Describe())
	}
}

func TestPacketLimiterAntiXrayDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "anticheat:\n  anti-xray:\n    enabled: false\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("anti-xray 关闭不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonXrayOff) {
		t.Fatalf("应告警 anti-xray 关闭: %s", a.Describe())
	}
}

func TestPacketLimiterAntiXrayEngine(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "anticheat:\n  anti-xray:\n    enabled: true\n    engine-mode: 7\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("引擎模式非法不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonXrayEngine) {
		t.Fatalf("应报告引擎模式非法: %s", a.Describe())
	}
}

func TestPacketLimiterAntiXrayEmptyBlocks(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "anticheat:\n  anti-xray:\n    enabled: true\n    engine-mode: 2\n    hidden-blocks: []\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("空方块列表不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonXrayEmpty) {
		t.Fatalf("应报告空列表: %s", a.Describe())
	}
}

func TestPacketLimiterAutoSaveBurst(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "chunk-loading:\n  max-auto-save-chunks-per-tick: 64\n  prevent-moving-into-unloaded-chunks: false\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("自动保存过密不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonAutoSave) {
		t.Fatalf("应报告自动保存过密: %s", a.Describe())
	}
}

func TestPacketLimiterOverrides(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileBody(t, dir, "config/paper-global.yml", "packet-limiter:\n  enabled: true\n  overrides:\n    packet_player_look:\n      max-packet-rate: 9000\n")
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() {
		t.Fatalf("覆盖项过宽不应阻断: %s", a.Describe())
	}
	if !pklHasReason(a, pklReasonLimiterLoose) {
		t.Fatalf("应报告覆盖项过宽: %s", a.Describe())
	}
}

func TestPacketLimiterSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yml")
	if err := os.WriteFile(target, []byte("packet-limiter:\n  enabled: true\n"), 0o644); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "config", "paper-global.yml")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditServerPacketLimiter(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接应阻断: %s", a.Describe())
	}
}

func TestPacketLimiterCleanConfig(t *testing.T) {
	dir := t.TempDir()
	body := "packet-limiter:\n  enabled: true\n  all-packets:\n    max-packet-rate: 300\n    interval: 7.0\n  kick-message: \"kick\"\nanticheat:\n  anti-xray:\n    enabled: true\n    engine-mode: 2\n    hidden-blocks: [copper_ore, deepslate_copper_ore]\n    replacement-blocks: [stone, deepslate]\nchunk-loading:\n  max-auto-save-chunks-per-tick: 8\n  prevent-moving-into-unloaded-chunks: true\n"
	auditWriteFileBody(t, dir, "config/paper-global.yml", body)
	a := AuditServerPacketLimiter(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合规配置不应产生问题: %s", a.Describe())
	}
}
