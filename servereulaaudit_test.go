package main

import (
	"os"
	"path/filepath"
	"testing"
)


func serEulaHas(findings []EulaFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestEulaMissing(t *testing.T) {
	a := AuditServerEula(t.TempDir())
	if a.Blocking() || !serEulaHas(a.Findings, serReasonMiss) {
		t.Fatalf("缺少 eula.txt 应告警: %v", a.Describe())
	}
}

func TestEulaAccepted(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "eula.txt", "#By changing the setting below to TRUE you agree\neula=true\n")
	a := AuditServerEula(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("已接受 EULA 不应报警: %v", a.Describe())
	}
}

func TestEulaDeclined(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "eula.txt", "eula=false\n")
	a := AuditServerEula(dir)
	if a.Blocking() || !serEulaHas(a.Findings, serReasonDecl) {
		t.Fatalf("未接受 EULA 应告警: %v", a.Describe())
	}
}

func TestEulaConflicting(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "eula.txt", "eula=true\neula=false\n")
	a := AuditServerEula(dir)
	if !a.Blocking() || !serEulaHas(a.Findings, serReasonConf) {
		t.Fatalf("冲突取值应阻断: %v", a.Describe())
	}
}

func TestEulaGarbageValue(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "eula.txt", "eula=maybe\n")
	a := AuditServerEula(dir)
	if !a.Blocking() || !serEulaHas(a.Findings, serReasonConf) {
		t.Fatalf("非法取值应阻断: %v", a.Describe())
	}
}

func TestEulaControlChars(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "eula.txt", "eula=true\u0000\n")
	a := AuditServerEula(dir)
	if !a.Blocking() || !serEulaHas(a.Findings, serReasonCtl) {
		t.Fatalf("控制字符应阻断: %v", a.Describe())
	}
}

func TestEulaSymlink(t *testing.T) {
	dir := t.TempDir()
	auditWriteFile(t, dir, "real.txt", "eula=true\n")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "eula.txt")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerEula(dir)
	if !a.Blocking() || !serEulaHas(a.Findings, serReasonLink) {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}
