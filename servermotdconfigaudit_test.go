package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func motWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func motHas(a *MotdConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestMotdConfigClean(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=A Minecraft Server\nenforce-secure-profile=true\nhide-online-players=true\nhide-version=true\n")
	a := AuditServerMotdConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
}

func TestMotdConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestMotdConfigEmptyDir(t *testing.T) {
	a := AuditServerMotdConfig("")
	if !motHas(a, motMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestMotdConfigMissingMOTD(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "enforce-secure-profile=true\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDEmpty) {
		t.Fatalf("未配置 motd 应提示: %v", a.Describe())
	}
}

func TestMotdConfigEmptyMOTD(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=\"\"\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDEmpty) {
		t.Fatalf("空 motd 应提示: %v", a.Describe())
	}
}

func TestMotdConfigTooLong(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd="+strings.Repeat("A", 600)+"\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDLong) {
		t.Fatalf("motd 超长应阻断: %v", a.Describe())
	}
}

func TestMotdConfigControlCharacters(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=A\x07B\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDControl) {
		t.Fatalf("控制字符应提示: %v", a.Describe())
	}
}

func TestMotdConfigFormattingCodes(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=\u00a7aHello\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDColor) {
		t.Fatalf("格式化代码应提示: %v", a.Describe())
	}
}

func TestMotdConfigAddressLeak(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=play.example.com\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDHost) {
		t.Fatalf("暴露域名应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("暴露域名应阻断: %v", a.Describe())
	}
}

func TestMotdConfigIPLeak(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=10.0.0.12\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motMOTDHost) {
		t.Fatalf("暴露 IP 应阻断: %v", a.Describe())
	}
}

func TestMotdConfigSecureProfileOff(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=A Minecraft Server\nenforce-secure-profile=false\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motSecureChat) {
		t.Fatalf("关闭签名聊天应提示: %v", a.Describe())
	}
}

func TestMotdConfigPlayersExposed(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=A Minecraft Server\nhide-online-players=false\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motHidePlayers) {
		t.Fatalf("玩家名单可见应提示: %v", a.Describe())
	}
}

func TestMotdConfigVersionExposed(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=A Minecraft Server\nhide-version=false\n")
	a := AuditServerMotdConfig(dir)
	if !motHas(a, motVersionLeak) {
		t.Fatalf("版本暴露应提示: %v", a.Describe())
	}
}

func TestMotdConfigBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "\ufeffmotd=\"A Minecraft Server\"\nenforce-secure-profile=\"true\"\n")
	a := AuditServerMotdConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}

func TestMotdConfigMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	motWrite(t, dir, "motd=10.0.0.12\nenforce-secure-profile=false\nhide-online-players=false\nhide-version=false\n")
	a := AuditServerMotdConfig(dir)
	if len(a.Findings) != 4 {
		t.Fatalf("应有 4 条发现: %v", a.Describe())
	}
}
