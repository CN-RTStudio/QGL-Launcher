package main

import (
	"testing"
)

func TestRconCleanDisabled(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=false\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if a.HasWarnings() {
		t.Fatalf("未开启 RCON 不应报警: %v", a.Describe())
	}
}

func TestRconEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=true\nrcon.password=\n")
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrRCONEmpty) || !a.Blocking() {
		t.Fatalf("空密码应阻断: %v", a.Describe())
	}
}

func TestRconShortPassword(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=true\nrcon.password=abc123\n")
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrRCONWeak) || !a.Blocking() {
		t.Fatalf("短密码应阻断: %v", a.Describe())
	}
}

func TestRconPlaceholderPassword(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=true\nrcon.password=changeme\n")
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrRCONDefault) || !a.Blocking() {
		t.Fatalf("占位密码应阻断: %v", a.Describe())
	}
}

func TestRconStrongPassword(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=true\nrcon.password=QingLong#2024x9\nrcon.port=25575\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if a.Blocking() {
		t.Fatalf("强密码不应阻断: %v", a.Describe())
	}
	if !auditHasReason(a, syrRCONEnabled) {
		t.Fatalf("开启 RCON 应留提示: %v", a.Describe())
	}
}

func TestRconPortCollision(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=true\nrcon.password=QingLong#2024x9\nrcon.port=25565\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrRCONPortCol) || !a.Blocking() {
		t.Fatalf("端口冲突应阻断: %v", a.Describe())
	}
}

func TestRconBadPort(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-rcon=true\nrcon.password=QingLong#2024x9\nrcon.port=99999\n")
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrRCONPortBad) {
		t.Fatalf("非法端口应告警: %v", a.Describe())
	}
}

func TestRconQueryEnabled(t *testing.T) {
	dir := t.TempDir()
	syqWrite(t, dir, "enable-query=true\nquery.port=25565\nserver-port=25565\n")
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrQueryEnabled) || !auditHasReason(a, syrQueryPortCol) {
		t.Fatalf("Query 暴露应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("Query 仅告警不阻断: %v", a.Describe())
	}
}

func TestRconMissingProps(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerRconHardening(dir)
	if !auditHasReason(a, syrMissing) {
		t.Fatalf("缺少属性文件应告警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("缺少文件不应阻断: %v", a.Describe())
	}
}
