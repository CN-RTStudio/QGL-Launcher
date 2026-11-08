package main

import (
	"os"
	"path/filepath"
	"testing"
)

func spvWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func spvHas(a *PrivilegeScopeAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestPrivilegeScopeClean(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "op-permission-level=2\nfunction-permission-level=2\nenforce-secure-profile=true\nwhite-list=true\nenforce-whitelist=true\nlevel-name=world\nresource-pack=https://example.com/pack.zip\n")
	a := AuditServerPrivilegeScope(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
	if a.Describe() == "" {
		t.Fatalf("描述不应为空")
	}
}

func TestPrivilegeScopeMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestPrivilegeScopeOpLevelHigh(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "op-permission-level=4\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvOpLevel) {
		t.Fatalf("管理员等级过高应提示: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("管理员等级过高不应阻断: %v", a.Describe())
	}
}

func TestPrivilegeScopeOpLevelInvalid(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "op-permission-level=off\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvOpLevel) {
		t.Fatalf("非整数等级应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非整数等级应阻断: %v", a.Describe())
	}
}

func TestPrivilegeScopeFuncLevelHigh(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "function-permission-level=4\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvFuncLevel) {
		t.Fatalf("函数等级过高应提示: %v", a.Describe())
	}
}

func TestPrivilegeScopeSecureProfileOff(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "enforce-secure-profile=false\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvSecureChat) {
		t.Fatalf("关闭安全档案应提示: %v", a.Describe())
	}
}

func TestPrivilegeScopeWhitelistOff(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "white-list=false\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvWhiteList) {
		t.Fatalf("关闭白名单应提示: %v", a.Describe())
	}
}

func TestPrivilegeScopeEnforceWhitelistOff(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "enforce-whitelist=false\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvEnforceList) {
		t.Fatalf("未强制白名单应提示: %v", a.Describe())
	}
}

func TestPrivilegeScopeLevelNameTraversal(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "level-name=../outside\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvLevelPath) {
		t.Fatalf("世界名穿越应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("世界名穿越应阻断: %v", a.Describe())
	}
}

func TestPrivilegeScopeLevelNameControl(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "level-name=world\u0007\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvLevelCtrl) {
		t.Fatalf("世界名控制字符应阻断: %v", a.Describe())
	}
}

func TestPrivilegeScopeResourcePackInsecure(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "resource-pack=http://example.com/pack.zip\n")
	a := AuditServerPrivilegeScope(dir)
	if !spvHas(a, spvPackScheme) {
		t.Fatalf("非 HTTPS 资源包应阻断: %v", a.Describe())
	}
}

func TestPrivilegeScopeBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "\ufeffop-permission-level=\"2\"\nlevel-name=\"world\"\nresource-pack=\"https://example.com/pack.zip\"\n")
	a := AuditServerPrivilegeScope(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}

func TestPrivilegeScopeMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	spvWrite(t, dir, "op-permission-level=4\nwhite-list=false\nlevel-name=../outside\nresource-pack=http://example.com/pack.zip\n")
	a := AuditServerPrivilegeScope(dir)
	if len(a.Findings) != 4 {
		t.Fatalf("应有 4 条发现: %v", a.Describe())
	}
}
