package main

import (
	"path/filepath"
	"testing"
)

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
	auditWriteFileBody(t, dir, "server.properties", "online-mode=false\nmotd=test\n")
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
	auditWriteFileBody(t, dir, "server.properties", "online-mode=false\n")
	auditWriteFileBody(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: true\n    secret: 0123456789abcdef0123456789abcdef\n")
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
	auditWriteFileBody(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: abc123\n")
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
	auditWriteFileBody(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: <secret>\n")
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
	auditWriteFileBody(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: false\n    secret: 0123456789abcdef0123456789abcdef\n")
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
