package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func propsOf(t *testing.T, text string) *serverProperties {
	t.Helper()
	return parseServerProperties([]byte(text))
}

func TestAuditServerSettingsCleanConfig(t *testing.T) {
	audit := AuditServerSettings(propsOf(t, "enable-rcon=false\nonline-mode=true\nmax-players=20\n"))
	if len(audit.Findings) != 0 || audit.Blocking() {
		t.Fatalf("干净配置不应产生发现项: %+v", audit.Findings)
	}
	if !strings.Contains(audit.Describe(), "未发现风险项") {
		t.Fatalf("描述不符: %s", audit.Describe())
	}
}

func TestAuditServerSettingsBlocksOpenRcon(t *testing.T) {
	audit := AuditServerSettings(propsOf(t, "enable-rcon=true\nrcon.password=\n"))
	if !audit.Blocking() {
		t.Fatalf("空 RCON 密码应阻断启动")
	}
	if len(audit.Codes()) == 0 || !strings.Contains(audit.Describe(), "critical") {
		t.Fatalf("发现项缺失: %s", audit.Describe())
	}
}

func TestAuditServerSettingsShortRconPasswordWarns(t *testing.T) {
	audit := AuditServerSettings(propsOf(t, "enable-rcon=true\nrcon.password=abc\nrcon.port=70000\n"))
	if audit.Blocking() {
		t.Fatalf("短密码仅告警，不应阻断")
	}
	if len(audit.Findings) != 2 {
		t.Fatalf("期望两条告警，实际 %+v", audit.Findings)
	}
}

func TestAuditServerSettingsOfflineModeWarns(t *testing.T) {
	audit := AuditServerSettings(propsOf(t, "online-mode=false\nenforce-secure-profile=false\nallow-flight=true\nmax-players=99999\n"))
	if audit.Blocking() || len(audit.Findings) != 4 {
		t.Fatalf("期望四条告警，实际 %+v", audit.Findings)
	}
}

func TestAuditServerSettingsResourcePackRequiresHTTPSAndSHA1(t *testing.T) {
	audit := AuditServerSettings(propsOf(t, "resource-pack=http://example.com/pack.zip\n"))
	if len(audit.Findings) != 1 || !strings.Contains(audit.Findings[0].Message, "https") {
		t.Fatalf("明文资源包应告警: %+v", audit.Findings)
	}
	audit = AuditServerSettings(propsOf(t, "resource-pack=https://example.com/pack.zip\n"))
	if len(audit.Findings) != 1 || !strings.Contains(audit.Findings[0].Key, "sha1") {
		t.Fatalf("缺摘要应告警: %+v", audit.Findings)
	}
	audit = AuditServerSettings(propsOf(t, "resource-pack=https://example.com/pack.zip\nresource-pack-sha1=0123456789abcdef0123456789abcdef01234567\n"))
	if len(audit.Findings) != 0 {
		t.Fatalf("https 加合法摘要不应告警: %+v", audit.Findings)
	}
}

func TestAuditServerSettingsFileMissingAndPresent(t *testing.T) {
	dir := t.TempDir()
	audit, err := AuditServerSettingsFile(dir)
	if err != nil || len(audit.Findings) != 0 {
		t.Fatalf("缺少文件应返回空审计: %+v %v", audit, err)
	}
	content := "enable-rcon=true\nrcon.password=\n"
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o600); err != nil {
		t.Fatalf("写入属性失败: %v", err)
	}
	audit, err = AuditServerSettingsFile(dir)
	if err != nil || !audit.Blocking() {
		t.Fatalf("应阻断开放 RCON: %+v %v", audit, err)
	}
}

func TestAuditServerSettingsFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.properties")
	if err := os.WriteFile(target, []byte("online-mode=false\n"), 0o600); err != nil {
		t.Fatalf("写入属性失败: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	if _, err := AuditServerSettingsFile(dir); err == nil {
		t.Fatalf("符号链接的 properties 应被拒绝")
	}
}

func TestAuditServerSettingsNilProperties(t *testing.T) {
	audit := AuditServerSettings(nil)
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("nil 输入应返回空审计")
	}
}
