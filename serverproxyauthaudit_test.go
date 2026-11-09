package main

import (
	"os"
	"path/filepath"
	"strings"
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

func TestProxyAuthVelocityPlaceholderSecret(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: \"changeme\"\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonNoSecret) || !a.Blocking() {
		t.Fatalf("占位 secret 应阻断: %v", a.Describe())
	}
}

func TestProxyAuthVelocityControlChars(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: \"abc"+"\x00"+"defghijkl\"\n")
	a := AuditServerProxyAuth(dir)
	if !a.Blocking() {
		t.Fatalf("控制字符应阻断: %v", a.Describe())
	}
}

func TestProxyAuthVelocityValidSecret(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\n")
	auditWriteFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: true\n    secret: \"abcdefghijklmnop\"\n")
	a := AuditServerProxyAuth(dir)
	if a.Blocking() {
		t.Fatalf("合法 velocity 配置不应阻断: %v", a.Describe())
	}
	if !spaHas(a.Findings, spaReasonDualProxy) {
		t.Fatalf("应记录 velocity 启用: %v", a.Describe())
	}
}

func TestProxyAuthBungeeWithoutLegacy(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "config/paper-global.yml", "proxies:\n  bungee-cord:\n    enabled: true\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonNoPaper) || !a.Blocking() {
		t.Fatalf("paper 代理缺 spigot 声明应阻断: %v", a.Describe())
	}
}

func TestProxyAuthOfflineModeWithoutProxy(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\nprevent-proxy-connections=false\n")
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonOffline) || !a.Blocking() {
		t.Fatalf("离线模式无代理应阻断: %v", a.Describe())
    }
	if !spaHas(a.Findings, spaReasonPreventOff) {
		t.Fatalf("应提示 prevent-proxy-connections: %v", a.Describe())
	}
}

func TestProxyAuthSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "spigot.yml")
	if err := os.WriteFile(outside, []byte("settings:\n  bungeecord: true\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "spigot.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonSymlink) || !a.Blocking() {
		t.Fatalf("符号链接配置应阻断: %v", a.Describe())
	}
}

func TestProxyAuthOversizeConfig(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("# padding\n", 60000)
	auditWriteFile(t, dir, "spigot.yml", big)
	a := AuditServerProxyAuth(dir)
	if !spaHas(a.Findings, spaReasonTooLarge) || !a.Blocking() {
		t.Fatalf("超大配置应阻断: %v", a.Describe())
	}
}

func TestProxyAuthDescribeTruncates(t *testing.T) {
	a := &ProxyAuthAudit{}
	for i := 0; i < 30; i++ {
		a.add("f.yml", spaReasonBadValue, strings.Repeat("x", 3), false)
	}
	text := a.Describe()
	if !strings.Contains(text, "等 30 项") {
		t.Fatalf("超限描述应截断: %s", text)
    }
}

func TestProxyAuthFindingsCapped(t *testing.T) {
	a := &ProxyAuthAudit{}
	for i := 0; i < 80; i++ {
		a.add("f.yml", spaReasonBadValue, "x", false)
	}
	if len(a.Findings) > spaMaxFindings {
		t.Fatalf("发现数超出上限: %d", len(a.Findings))
	}
}
