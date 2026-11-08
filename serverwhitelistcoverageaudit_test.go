package main

import (
	"os"
	"path/filepath"
	"testing"
)

func swcWrite(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func swcHas(a *WhitelistCoverageAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestWhitelistCoverageClean(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=true\nenforce-whitelist=true\n")
	swcWrite(t, dir, "whitelist.json", `[{"uuid":"1111","name":"alice"}]`)
	if a := AuditServerWhitelistCoverage(dir); a.HasWarnings() {
		t.Fatalf("白名单配置一致不应报警: %v", a.Describe())
	}
}

func TestWhitelistCoverageEnforceWithoutList(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=false\nenforce-whitelist=true\n")
	a := AuditServerWhitelistCoverage(dir)
	if !a.Blocking() || !swcHas(a, swcEnforceBad) {
		t.Fatalf("强制白名单但白名单关闭应阻断: %v", a.Describe())
	}
}

func TestWhitelistCoverageEnabledNoFile(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=true\n")
	a := AuditServerWhitelistCoverage(dir)
	if !a.Blocking() || !swcHas(a, swcOnNoFile) {
		t.Fatalf("白名单缺失应阻断: %v", a.Describe())
	}
}

func TestWhitelistCoverageStaleList(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=false\n")
	swcWrite(t, dir, "whitelist.json", `[{"uuid":"1111","name":"alice"}]`)
	a := AuditServerWhitelistCoverage(dir)
	if !swcHas(a, swcOffButList) {
		t.Fatalf("白名单关闭但残留条目应提示: %v", a.Describe())
	}
}

func TestWhitelistCoverageBadJSON(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=true\n")
	swcWrite(t, dir, "whitelist.json", "{")
	a := AuditServerWhitelistCoverage(dir)
	if !a.Blocking() || !swcHas(a, swcBadJSON) {
		t.Fatalf("非法 JSON 应阻断: %v", a.Describe())
	}
}

func TestWhitelistCoverageDuplicateAndMissingUUID(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=true\n")
	swcWrite(t, dir, "whitelist.json", `[{"uuid":"","name":"alice"},{"uuid":"2","name":"Alice"}]`)
	a := AuditServerWhitelistCoverage(dir)
	if !swcHas(a, swcNoUUID) || !swcHas(a, swcDupName) {
		t.Fatalf("应报告缺 UUID 与重复名: %v", a.Describe())
	}
}

func TestWhitelistCoverageOpNotListed(t *testing.T) {
	dir := t.TempDir()
	swcWrite(t, dir, "server.properties", "white-list=true\n")
	swcWrite(t, dir, "whitelist.json", `[{"uuid":"1","name":"alice"}]`)
	swcWrite(t, dir, "ops.json", `[{"uuid":"9","name":"bob","level":4}]`)
	a := AuditServerWhitelistCoverage(dir)
	if !swcHas(a, swcOpNotListed) {
		t.Fatalf("管理员缺席白名单应提示: %v", a.Describe())
	}
}
