package main

import (
	"testing"
)


func sccHas(findings []ConsistencyFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestConsistencyClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=true\nwhite-list=true\nenforce-secure-profile=true\nenable-rcon=false\nview-distance=10\nsimulation-distance=8\nmax-players=20\n")
	if a := AuditServerConfigConsistency(dir); a.HasWarnings() {
		t.Fatalf("一致配置不应报警: %v", a.Describe())
	}
}

func TestConsistencyOfflineMode(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "online-mode=false\n")
	a := AuditServerConfigConsistency(dir)
	if !a.Blocking() || !sccHas(a.Findings, sccReasonOnline) {
		t.Fatalf("离线模式应阻断: %v", a.Describe())
	}
}

func TestConsistencyRconWeak(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "enable-rcon=true\nrcon.password=changeme\n")
	a := AuditServerConfigConsistency(dir)
	if !a.Blocking() || !sccHas(a.Findings, sccReasonRconPass) {
		t.Fatalf("弱 RCON 密码应阻断: %v", a.Describe())
	}
}

func TestConsistencyDistance(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "server.properties", "view-distance=6\nsimulation-distance=10\n")
	a := AuditServerConfigConsistency(dir)
	if !sccHas(a.Findings, sccReasonDistance) {
		t.Fatalf("视距不一致应报警: %v", a.Describe())
	}
}
