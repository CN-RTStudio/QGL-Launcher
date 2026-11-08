package main

import (
	"os"
	"path/filepath"
	"testing"
)

func syrWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write props: %v", err)
	}
}

func syrHas(a *RconHardeningAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestRconCleanDisabled(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=false\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if a.HasWarnings() {
		t.Fatalf("未开启 RCON 不应报警: %v", a.Describe())
	}
}

func TestRconEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=true\nrcon.password=\n")
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrRCONEmpty) || !a.Blocking() {
		t.Fatalf("空密码应阻断: %v", a.Describe())
	}
}

func TestRconShortPassword(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=true\nrcon.password=abc123\n")
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrRCONWeak) || !a.Blocking() {
		t.Fatalf("短密码应阻断: %v", a.Describe())
	}
}

func TestRconPlaceholderPassword(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=true\nrcon.password=changeme\n")
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrRCONDefault) || !a.Blocking() {
		t.Fatalf("占位密码应阻断: %v", a.Describe())
	}
}

func TestRconStrongPassword(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=true\nrcon.password=QingLong#2024x9\nrcon.port=25575\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if a.Blocking() {
		t.Fatalf("强密码不应阻断: %v", a.Describe())
	}
	if !syrHas(a, syrRCONEnabled) {
		t.Fatalf("开启 RCON 应留提示: %v", a.Describe())
	}
}

func TestRconPortCollision(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=true\nrcon.password=QingLong#2024x9\nrcon.port=25565\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrRCONPortCol) || !a.Blocking() {
		t.Fatalf("端口冲突应阻断: %v", a.Describe())
	}
}

func TestRconBadPort(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-rcon=true\nrcon.password=QingLong#2024x9\nrcon.port=99999\n")
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrRCONPortBad) {
		t.Fatalf("非法端口应告警: %v", a.Describe())
	}
}

func TestRconQueryEnabled(t *testing.T) {
	dir := t.TempDir()
	syrWrite(t, dir, "enable-query=true\nquery.port=25565\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrQueryEnabled) || !syrHas(a, syrQueryPortCol) {
		t.Fatalf("Query 暴露应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("Query 仅告警不阻断: %v", a.Describe())
	}
}

func TestRconMissingProps(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerRconHardening(dir)
	if !syrHas(a, syrMissing) {
		t.Fatalf("缺少属性文件应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("缺少文件不应阻断: %v", a.Describe())
	}
}
