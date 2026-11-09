package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxySecretFileMissingWarns(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonSecretMissing) {
		t.Fatalf("want secret-file-missing, got %v", a.Codes())
	}
}

func TestProxySecretFilePermissiveWarns(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n")
	path := filepath.Join(dir, "forwarding.secret")
	if err := os.WriteFile(path, []byte("abcdefghijklmnop"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o644)
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonSecretPermissive) {
		t.Fatalf("want permissive secret, got %v", a.Codes())
	}
}

func TestProxySecretSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n")
	real := filepath.Join(dir, "real.secret")
	if err := os.WriteFile(real, []byte("abcdefghijklmnop"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "forwarding.secret")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonSecretSymlink) || !a.Blocking() {
		t.Fatalf("want secret symlink block, got %v", a.Codes())
	}
}

func TestProxyDuplicateKeyWarns(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    enabled: false\n    secret: 'abcdefghijklmnop'\n")
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonDuplicateKey) {
		t.Fatalf("want duplicate-key, got %v", a.Codes())
	}
}

func TestProxyYAMLSymlinkBlocks(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	real := filepath.Join(dir, "paper-real.yml")
	if err := os.WriteFile(real, []byte("proxies:\n  velocity:\n    enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "config-paper-global.yml")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "config", "paper-global.yml")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerProxyTrust(dir)
	if !proxyHas(a, proxyReasonSymlink) || !a.Blocking() {
		t.Fatalf("want symlink block, got %v", a.Codes())
	}
}

func TestProxyYAMLCommentsIgnored(t *testing.T) {
	data := []byte("# proxies:\nproxies:\n  velocity:\n    enabled: true # comment\n    secret: 'abc#def'\n")
	flat, dups := flattenYAML(data)
	if len(dups) != 0 {
		t.Fatalf("dups=%v", dups)
	}
	if flat["proxies.velocity.enabled"] != "true" {
		t.Fatalf("enabled=%q", flat["proxies.velocity.enabled"])
	}
	if flat["proxies.velocity.secret"] != "abc#def" {
		t.Fatalf("secret=%q", flat["proxies.velocity.secret"])
	}
}

func TestProxyDescribeKeepsValues(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=0.0.0.0\nonline-mode=false\n")
	writeProxyFile(t, dir, "config/paper-global.yml", "proxies:\n  velocity:\n    enabled: true\n    secret: 'abcdefghijklmnop'\n")
	a := AuditServerProxyTrust(dir)
	d := a.Describe()
	if !strings.Contains(d, "proxy-exposed") || !strings.Contains(d, "0.0.0.0") {
		t.Fatalf("describe=%q", d)
	}
	if d != a.Describe() {
		t.Fatalf("describe unstable")
	}
}

func TestProxySummaryMentionsProvider(t *testing.T) {
	dir := t.TempDir()
	writeProxyFile(t, dir, "server.properties", "server-ip=127.0.0.1\nonline-mode=true\n")
	writeProxyFile(t, dir, "spigot.yml", "settings:\n  bungeecord: true\n")
	a := AuditServerProxyTrust(dir)
	if !strings.Contains(a.Summary(), "bungeecord") {
		t.Fatalf("summary=%q", a.Summary())
	}
}
