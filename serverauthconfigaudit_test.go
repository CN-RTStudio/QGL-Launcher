package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sauWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sauHas(a *AuthConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAuthConfigClean(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "online-mode=true\nprevent-proxy-connections=true\nmax-players=20\nnetwork-compression-threshold=256\nserver-ip=127.0.0.1\nplayer-idle-timeout=0\n")
	a := AuditServerAuthConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
}

func TestAuthConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestAuthConfigEmptyDir(t *testing.T) {
	a := AuditServerAuthConfig("")
	if !sauHas(a, sauMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestAuthConfigOnlineModeOff(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "online-mode=false\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauOnlineOff) {
		t.Fatalf("关闭正版验证应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("关闭正版验证应阻断: %v", a.Describe())
	}
}

func TestAuthConfigProxyAllowed(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "prevent-proxy-connections=false\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauProxyOff) {
		t.Fatalf("允许代理应提示: %v", a.Describe())
	}
}

func TestAuthConfigMaxPlayersInvalid(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "max-players=-1\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauMaxPlayers) {
		t.Fatalf("人数下限应阻断: %v", a.Describe())
	}
}

func TestAuthConfigMaxPlayersHigh(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "max-players=500\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauMaxPlayers) {
		t.Fatalf("人数过高应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("人数过高不应阻断: %v", a.Describe())
	}
}

func TestAuthConfigCompressionInvalid(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "network-compression-threshold=999999\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauCompress) {
		t.Fatalf("压缩阈值越界应提示: %v", a.Describe())
	}
}

func TestAuthConfigBindAll(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "server-ip=\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauBindAll) {
		t.Fatalf("未指定监听地址应提示: %v", a.Describe())
	}
}

func TestAuthConfigIdleTimeoutInvalid(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "player-idle-timeout=-5\n")
	a := AuditServerAuthConfig(dir)
	if !sauHas(a, sauIdleTimeout) {
		t.Fatalf("空闲超时越界应提示: %v", a.Describe())
	}
}

func TestAuthConfigBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "\ufeffonline-mode=\"true\"\nmax-players=\"20\"\n")
	a := AuditServerAuthConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}

func TestAuthConfigMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	sauWrite(t, dir, "online-mode=false\nprevent-proxy-connections=false\nmax-players=-1\nserver-ip=\n")
	a := AuditServerAuthConfig(dir)
	if len(a.Findings) != 4 {
		t.Fatalf("应有 4 条发现: %v", a.Describe())
	}
	if a.Findings[0].Reason != sauOnlineOff && a.Findings[0].Reason != sauMaxPlayers && a.Findings[0].Reason != sauProxyOff && a.Findings[0].Reason != sauBindAll {
		t.Fatalf("发现项来自规则表: %v", a.Describe())
	}
}
