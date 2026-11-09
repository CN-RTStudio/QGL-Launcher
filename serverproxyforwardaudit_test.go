package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pfwTestWrite(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("写入 %s 失败: %v", rel, err)
	}
}

func pfwHasReason(a *ProxyForwardAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestProxyForwardMissingDir(t *testing.T) {
	a := AuditServerProxyForwarding("")
	if a.Blocking() {
		t.Fatalf("未配置目录不应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonMissing) {
		t.Fatalf("应报告缺少目录: %s", a.Describe())
	}
}

func TestProxyForwardNonexistentDir(t *testing.T) {
	a := AuditServerProxyForwarding(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("目录不存在不应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonMissing) {
		t.Fatalf("应报告目录不存在: %s", a.Describe())
	}
}

func TestProxyForwardEmptyServer(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerProxyForwarding(dir)
	if a.Blocking() {
		t.Fatalf("空服务器不应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonMissing) {
		t.Fatalf("空服务器应报告缺少配置: %s", a.Describe())
	}
}

func TestProxyForwardOfflineWithoutProxy(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "server.properties", "online-mode=false\nmotd=test\n")
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("离线模式且无代理应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonOfflineExposed) {
		t.Fatalf("应报告离线暴露: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonOffline) {
		t.Fatalf("应同时给出离线提示: %s", a.Describe())
	}
}

func TestProxyForwardOfflineBehindVelocity(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "server.properties", "online-mode=false\n")
	pfwTestWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: true\n    secret: 0123456789abcdef0123456789abcdef\n")
	a := AuditServerProxyForwarding(dir)
	if a.Blocking() {
		t.Fatalf("受信代理下离线模式不应阻断: %s", a.Describe())
	}
	if a.ProxyKind != "velocity" {
		t.Fatalf("应识别 velocity 代理: %s", a.ProxyKind)
	}
}

func TestProxyForwardShortSecret(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: abc123\n")
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("短密钥应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonWeakSecret) {
		t.Fatalf("应报告弱密钥: %s", a.Describe())
	}
}

func TestProxyForwardPlaceholderSecret(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: <secret>\n")
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("占位密钥应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonWeakSecret) {
		t.Fatalf("应报告占位密钥: %s", a.Describe())
	}
}

func TestProxyForwardProxyOfflineMode(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: false\n    secret: 0123456789abcdef0123456789abcdef\n")
	a := AuditServerProxyForwarding(dir)
	if a.Blocking() {
		t.Fatalf("代理离线模式不应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonProxyOnline) {
		t.Fatalf("应报告代理离线模式: %s", a.Describe())
	}
	if !a.HasWarnings() {
		t.Fatalf("应有告警: %s", a.Describe())
	}
}

func TestProxyForwardLegacyBungee(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n")
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("旧式 BungeeCord 转发应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonLegacyBungee) {
		t.Fatalf("应报告旧式转发: %s", a.Describe())
	}
}

func TestProxyForwardConflictingModes(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 0123456789abcdef0123456789abcdef\n  bungee-cord:\n    enabled: true\n")
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("双代理同时启用应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonConflict) {
		t.Fatalf("应报告代理模式冲突: %s", a.Describe())
	}
}

func TestProxyForwardUncheckedForwarding(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "server.properties", "online-mode=true\nprevent-proxy-connections=false\nenforce-secure-profile=false\n")
	a := AuditServerProxyForwarding(dir)
	if a.Blocking() {
		t.Fatalf("未校验转发不应阻断: %s", a.Describe())
	}
	count := 0
	for _, f := range a.Findings {
		if f.Reason == pfwReasonUncheckedForward {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("应报告两项转发未校验, 实际 %d: %s", count, a.Describe())
	}
}

func TestProxyForwardBadBungeeValue(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "spigot.yml", "settings:\n  bungeecord: maybe\n")
	a := AuditServerProxyForwarding(dir)
	if a.Blocking() {
		t.Fatalf("非法取值不应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonBadValue) {
		t.Fatalf("应报告非法取值: %s", a.Describe())
	}
}

func TestProxyForwardSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(target, []byte("online-mode=true\n"), 0o644); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	link := filepath.Join(dir, "server.properties")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接配置应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonSymlink) {
		t.Fatalf("应报告符号链接: %s", a.Describe())
	}
}

func TestProxyForwardOversizedProperties(t *testing.T) {
	dir := t.TempDir()
	body := "online-mode=true\nmotd=" + strings.Repeat("a", pfwMaxProps+16) + "\n"
	pfwTestWrite(t, dir, "server.properties", body)
	a := AuditServerProxyForwarding(dir)
	if !a.Blocking() {
		t.Fatalf("超大配置应阻断: %s", a.Describe())
	}
	if !pfwHasReason(a, pfwReasonTooLarge) {
		t.Fatalf("应报告体积超限: %s", a.Describe())
	}
}

func TestProxyForwardCleanConfig(t *testing.T) {
	dir := t.TempDir()
	pfwTestWrite(t, dir, "server.properties", "online-mode=true\nprevent-proxy-connections=true\nenforce-secure-profile=true\n")
	pfwTestWrite(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: true\n    secret: 0123456789abcdef0123456789abcdef\n")
	a := AuditServerProxyForwarding(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合规配置不应产生问题: %s", a.Describe())
	}
}
