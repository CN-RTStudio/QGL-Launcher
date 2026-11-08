package main

import (
	"os"
	"path/filepath"
	"testing"
)

func snaWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func snaHas(a *NetworkAbuseAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestNetworkAbuseClean(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "online-mode=true\nprevent-proxy-connections=true\nrate-limit=50\nnetwork-compression-threshold=256\nmax-players=20\nplayer-idle-timeout=5\nallow-flight=false\n")
	a := AuditServerNetworkAbuse(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}

func TestNetworkAbuseMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestNetworkAbuseEmptyDir(t *testing.T) {
	a := AuditServerNetworkAbuse("")
	if !snaHas(a, snaMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestNetworkAbuseOnlineModeOff(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "online-mode=false\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaOnlineOff) {
		t.Fatalf("离线模式应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("离线模式应阻断: %v", a.Describe())
	}
}

func TestNetworkAbuseProxyBypass(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "prevent-proxy-connections=false\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaProxyBypass) {
		t.Fatalf("代理直连应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("代理直连不应阻断: %v", a.Describe())
	}
}

func TestNetworkAbuseRateLimitZero(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "rate-limit=0\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaRateLimit) {
		t.Fatalf("无限速应提示: %v", a.Describe())
	}
}

func TestNetworkAbuseRateLimitInvalid(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "rate-limit=fast\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaRateLimit) {
		t.Fatalf("非整数限速应记录: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非整数限速应阻断: %v", a.Describe())
	}
}

func TestNetworkAbuseCompressionOff(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "network-compression-threshold=-1\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaCompress) {
		t.Fatalf("关闭压缩应提示: %v", a.Describe())
	}
}

func TestNetworkAbuseMaxPlayersExcessive(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "max-players=300\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaMaxPlayers) {
		t.Fatalf("玩家上限过大应提示: %v", a.Describe())
	}
}

func TestNetworkAbuseIdleTimeoutOff(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "player-idle-timeout=0\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaIdleKick) {
		t.Fatalf("不休眠踢出应提示: %v", a.Describe())
	}
}

func TestNetworkAbuseAllowFlight(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "allow-flight=true\n")
	a := AuditServerNetworkAbuse(dir)
	if !snaHas(a, snaAllowFlight) {
		t.Fatalf("放行飞行应提示: %v", a.Describe())
	}
}

func TestNetworkAbuseMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	snaWrite(t, dir, "online-mode=false\nrate-limit=0\nallow-flight=true\n")
	a := AuditServerNetworkAbuse(dir)
	if len(a.Findings) != 3 {
		t.Fatalf("应有 3 条发现: %v", a.Describe())
	}
	if !a.HasWarnings() || !a.Blocking() {
		t.Fatalf("应告警且阻断: %v", a.Describe())
	}
}
