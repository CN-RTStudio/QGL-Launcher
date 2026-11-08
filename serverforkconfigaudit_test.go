package main

import (
	"os"
	"path/filepath"
	"testing"
)

func fkWrite(t *testing.T, dir, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "bukkit.yml")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	return path
}

func fkHas(a ForkConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestForkConfigClean(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "settings:\n  connection-throttle: 4000\n  bungeecord: false\n", 0o600)
	a := AuditServerForkConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("期望无告警，得到 %s", a.Describe())
	}
}

func TestForkConfigThrottleOff(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "settings:\n  connection-throttle: -1\n", 0o600)
	a := AuditServerForkConfig(dir)
	if !fkHas(a, fkReasonThrottleOff) {
		t.Fatalf("期望 connection-throttle-off，得到 %s", a.Describe())
	}
}

func TestForkConfigLegacyProxy(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "settings:\n  bungeecord: true\n", 0o600)
	a := AuditServerForkConfig(dir)
	if !fkHas(a, fkReasonLegacyProxy) {
		t.Fatalf("期望 legacy-proxy-enabled，得到 %s", a.Describe())
	}
}

func TestForkConfigVelocitySecretEmpty(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "settings:\n  velocity-support.enabled: true\n  velocity-support.secret: ''\n", 0o600)
	a := AuditServerForkConfig(dir)
	if !fkHas(a, fkReasonProxySecret) || !a.Blocking() {
		t.Fatalf("期望代理密钥阻断，得到 %s", a.Describe())
	}
}

func TestForkConfigLimits(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "max-entity-collisions: 16\nview-distance: 32\npacket-limiter:\n  enabled: false\n  max-packet-rate: 900\n", 0o600)
	a := AuditServerForkConfig(dir)
	for _, reason := range []string{fkReasonCollisions, fkReasonViewDistance, fkReasonPacketLimiter, fkReasonPacketRate} {
		if !fkHas(a, reason) {
			t.Fatalf("缺少 %s，得到 %s", reason, a.Describe())
		}
	}
}

func TestForkConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "bukkit.yml")
	if err := os.WriteFile(target, []byte("x: 1\n"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "bukkit.yml")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	a := AuditServerForkConfig(dir)
	if !fkHas(a, fkReasonSymlink) || !a.Blocking() {
		t.Fatalf("期望 symlink 阻断，得到 %s", a.Describe())
	}
}

func TestForkConfigWorldWritable(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "settings:\n  bungeecord: false\n", 0o666)
	a := AuditServerForkConfig(dir)
	if !fkHas(a, fkReasonWorldWritable) || !a.Blocking() {
		t.Fatalf("期望 world-writable 阻断，得到 %s", a.Describe())
	}
}

func TestForkConfigPlainHTTP(t *testing.T) {
	dir := t.TempDir()
	fkWrite(t, dir, "settings:\n  update-url: http://example.invalid/paper.jar\n", 0o600)
	a := AuditServerForkConfig(dir)
	if !fkHas(a, fkReasonUnknownValue) {
		t.Fatalf("期望明文 http 告警，得到 %s", a.Describe())
	}
}

func TestForkConfigMissingFiles(t *testing.T) {
	a := AuditServerForkConfig(t.TempDir())
	if a.HasWarnings() {
		t.Fatalf("无分支配置时不应告警，得到 %s", a.Describe())
	}
}

func TestForkConfigMissingDir(t *testing.T) {
	a := AuditServerForkConfig(filepath.Join(t.TempDir(), "absent"))
	if !a.Blocking() {
		t.Fatalf("期望目录缺失阻断，得到 %s", a.Describe())
	}
}
