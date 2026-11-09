package main

import (
	"os"
	"path/filepath"
	"testing"
)

func spaHas(findings []ProxyAuthFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestProxyAuthMissingDir(t *testing.T) {
	a := AuditServerProxyAuth(filepath.Join(t.TempDir(), "absent"))
	if !spaHas(a.Findings, spaReasonMissing) {
		t.Fatalf("期望 missing，得到 %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("目录缺失不应阻断")
	}
}

func TestProxyAuthEmptyDir(t *testing.T) {
	a := AuditServerProxyAuth(t.TempDir())
	if len(a.Findings) != 0 {
		t.Fatalf("空目录应无发现，得到 %v", a.Describe())
	}
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("空目录不应告警")
	}
}

func TestProxyAuthSymlinkDir(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerProxyAuth(link)
	if !a.Blocking() {
		t.Fatalf("符号链接目录应阻断: %v", a.Describe())
	}
}

func TestProxyAuthLegacyWithoutToken(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\n")
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonLegacy) {
		t.Fatalf("应识别 legacy 转发: %v", a.Describe())
	}
	if !spaHas(a.Findings, spaReasonNoToken) || !a.Blocking() {
		t.Fatalf("缺 token 应阻断: %v", a.Describe())
	}
}

func TestProxyAuthLegacyShortToken(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\n")
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n  bungeeguard-token: \"abc\"\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonTokenWeak) || !a.Blocking() {
		t.Fatalf("短 token 应阻断: %v", a.Describe())
	}
}

func TestProxyAuthLegacyValidToken(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\n")
	auditWriteFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n  bungeeguard-token: \"0123456789abcdef\"\n")
	a := AuditServerProxyAuth(dir)
	if a.Blocking() {
		t.Fatalf("合法 token 不应阻断: %v", a.Describe())
	}
}

func TestProxyAuthVelocityMissingSecret(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\n")
	auditWriteFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: \"\"\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonNoSecret) || !a.Blocking() {
		t.Fatalf("空 secret 应阻断: %v", a.Describe())
	}
}

func TestProxyAuthVelocityWeakSecret(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: \"short\"\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonWeak) || !a.Blocking() {
		t.Fatalf("弱 secret 应阻断: %v", a.Describe())
	}
}
