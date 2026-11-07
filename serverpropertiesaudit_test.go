package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func prpWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func prpHas(a *PropertiesAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const prpHardened = `online-mode=true
enable-rcon=false
enable-query=false
white-list=true
enforce-whitelist=true
spawn-protection=16
max-players=20
level-name=world
server-port=25565
`

func TestPropertiesHardened(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened)
	a := AuditServerProperties(dir)
	if a.HasWarnings() {
		t.Fatalf("加固配置不应报警: %v", a.Describe())
	}
}

func TestPropertiesMissing(t *testing.T) {
	a := AuditServerProperties(t.TempDir())
	if !prpHas(a, prpMiss) {
		t.Fatalf("缺少配置应记录: %v", a.Describe())
	}
}

func TestPropertiesEmptyDir(t *testing.T) {
	a := AuditServerProperties("")
	if !prpHas(a, prpMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestPropertiesEmptyFile(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, "\n  \n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpEmpty) {
		t.Fatalf("空配置应记录: %v", a.Describe())
	}
}

func TestPropertiesOfflineMode(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"online-mode=false\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpOffline) || !a.Blocking() {
		t.Fatalf("离线模式应阻断: %v", a.Describe())
	}
}

func TestPropertiesRconNoPassword(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"enable-rcon=true\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpRconOpen) {
		t.Fatalf("RCON 无密码应阻断: %v", a.Describe())
	}
}

func TestPropertiesRconShortPassword(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"enable-rcon=true\nrcon.password=abc\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpRconWeak) {
		t.Fatalf("RCON 弱密码应提示: %v", a.Describe())
	}
}

func TestPropertiesRconBroadcast(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"enable-rcon=true\nrcon.password=longenough\nbroadcast-rcon-to-ops=true\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpRconBroadcast) {
		t.Fatalf("RCON 广播应提示: %v", a.Describe())
	}
}

func TestPropertiesQueryEnabled(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"enable-query=true\nquery.port=25565\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpQueryOpen) || !prpHas(a, prpPortClash) {
		t.Fatalf("Query 暴露与端口冲突应提示: %v", a.Describe())
	}
}

func TestPropertiesWhiteListOff(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, "online-mode=true\nwhite-list=false\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpWhiteListOff) {
		t.Fatalf("白名单关闭应提示: %v", a.Describe())
	}
}

func TestPropertiesEnforceOff(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"enforce-whitelist=false\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpEnforceOff) {
		t.Fatalf("未强制白名单应提示: %v", a.Describe())
	}
}

func TestPropertiesSpawnZero(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"spawn-protection=0\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpSpawnZero) {
		t.Fatalf("出生点保护为 0 应提示: %v", a.Describe())
	}
}

func TestPropertiesLevelTraversal(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"level-name=../outside\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpLevelTraverse) || !a.Blocking() {
		t.Fatalf("世界目录路径穿越应阻断: %v", a.Describe())
	}
}

func TestPropertiesMaxPlayers(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, prpHardened+"max-players=500\n")
	a := AuditServerProperties(dir)
	if !prpHas(a, prpPlayerLimit) {
		t.Fatalf("超量人数应提示: %v", a.Describe())
	}
}

func TestPropertiesQuotedValue(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, "online-mode=\"true\"\n#comment\nwhite-list=true\nenforce-whitelist=true\n")
	a := AuditServerProperties(dir)
	if a.HasWarnings() {
		t.Fatalf("带引号的合法配置不应报警: %v", a.Describe())
	}
	if a.Values["online-mode"] != "true" {
		t.Fatalf("引号应被剥离: %q", a.Values["online-mode"])
	}
}

func TestPropertiesAuditBOM(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, "\ufeff"+prpHardened)
	a := AuditServerProperties(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 的加固配置不应报警: %v", a.Describe())
	}
}

func TestPropertiesDescribeJoins(t *testing.T) {
	dir := t.TempDir()
	prpWrite(t, dir, "online-mode=false\nwhite-list=false\n")
	a := AuditServerProperties(dir)
	desc := a.Describe()
	if !strings.Contains(desc, prpOffline) || !strings.Contains(desc, prpWhiteListOff) {
		t.Fatalf("描述应含两类原因: %s", desc)
	}
}
