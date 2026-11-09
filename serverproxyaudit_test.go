package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProxyFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func proxyHas(a *ServerProxyAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestProxyMissingDir(t *testing.T) {
	a := AuditServerProxyTrust(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("missing dir should not block")
	}
	if !proxyHas(a, proxyReasonMissing) {
		t.Fatalf("codes=%v", a.Codes())
	}
}

func TestProxyNoConfig(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	a := AuditServerProxyTrust(dir)
	if a.ProxyEnabled {
		t.Fatalf("proxy should be disabled")
	}
	if a.Blocking() {
		t.Fatalf("no proxy should not block: %v", a.Codes())
	}
}

func TestProxyVelocityLoopbackClean(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=false\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    online-mode: true\n    secret: 'abcdefghijklmnop'\n")
	a := AuditServerProxyTrust(dir)
	if !a.ProxyEnabled || a.Provider != "velocity" {
		t.Fatalf("provider=%s enabled=%v", a.Provider, a.ProxyEnabled)
	}
	if a.Blocking() {
		t.Fatalf("loopback velocity should pass: %s", a.Describe())
	}
}

func TestProxyWildcardBindBlocks(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=\nonline-mode=false\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'abcdefghijklmnop'\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonProxyExposed) || !a.Blocking() {
		t.Fatalf("want proxy-exposed blocking, got %v", a.Codes())
	}
}

func TestProxyPublicBindBlocks(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=203.0.113.7\nonline-mode=false\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'abcdefghijklmnop'\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonProxyExposed) {
		t.Fatalf("want proxy-exposed, got %v", a.Codes())
	}
}

func TestProxyOnlineModeOffBlocks(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=0.0.0.0\nonline-mode=false\n")
	writeProxyFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonOnlineModeOff) || !a.Blocking() {
		t.Fatalf("want online-mode-off, got %v", a.Codes())
	}
}

func TestProxyLegacyBungeeWarns(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n")
	a := AuditServerProxyTrust(dir)
	if !a.ProxyEnabled || a.Provider != "bungeecord" {
		t.Fatalf("provider=%s enabled=%v", a.Provider, a.ProxyEnabled)
	}
	if !proxyHas(a, proxyReasonLegacyBungee) {
		t.Fatalf("want legacy-bungee, got %v", a.Codes())
	}
}

func TestProxyVelocityPlaceholderSecretBlocks(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'changeme'\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonPlaceholderSecret) || !a.Blocking() {
		t.Fatalf("want placeholder secret block, got %v", a.Codes())
	}
}

func TestProxyVelocityShortSecretWarns(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'short'\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonWeakSecret) {
		t.Fatalf("want weak secret, got %v", a.Codes())
	}
	if a.Blocking() {
		t.Fatalf("short secret should warn only")
	}
}

func TestProxySecretFileUsed(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n")
	writeProxyFile(t, dir, "forwarding.secret", "abcdefghijklmnop\n")
	a := AuditServerProxyTrust(dir)
	if a.Blocking() {
		t.Fatalf("secret file should pass: %s", a.Describe())
	}
}
