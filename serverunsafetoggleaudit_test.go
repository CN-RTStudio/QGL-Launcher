package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sunWriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sunHas(findings []UnsafeToggleFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

const sunGoodConfig = `unsupported-settings:
  perform-username-validation: true
  allow-perm-gen: false
`

func TestUnsafeToggleMissingDir(t *testing.T) {
	a := AuditServerUnsafeToggles(filepath.Join(t.TempDir(), "absent"))
	if !sunHas(a.Findings, sunReasonMissing) {
		t.Fatalf("期望 missing: %v", a.Describe())
    }
}

func TestUnsafeToggleGoodConfig(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "config/paper-global.yml", sunGoodConfig)
	a := AuditServerUnsafeToggles(dir)
	if len(a.Findings) != 0 {
		t.Fatalf("合规配置不应有发现: %v", a.Describe())
	}
}

func TestUnsafeToggleUsernameOff(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "config/paper-global.yml", strings.Replace(sunGoodConfig, "perform-username-validation: true", "perform-username-validation: false", 1))
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonUsername) || !a.Blocking() {
		t.Fatalf("关闭校验应阻断: %v", a.Describe())
	}
}

func TestUnsafeTogglePermGen(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "config/paper-global.yml", strings.Replace(sunGoodConfig, "allow-perm-gen: false", "allow-perm-gen: true", 1))
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonPermGen) || !a.Blocking() {
		t.Fatalf("权限生成应阻断: %v", a.Describe())
	}
}

func TestUnsafeToggleGenericToggle(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "config/paper-global.yml", sunGoodConfig+"  allow-unsafe-teleport: true\n")
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonToggle) || !a.Blocking() {
		t.Fatalf("未知实验开关应阻断: %v", a.Describe())
	}
}

func TestUnsafeToggleSecureProfile(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "server.properties", "enforce-secure-profile=false\n")
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonSecureOff) || a.Blocking() {
		t.Fatalf("未签名聊天应告警: %v", a.Describe())
	}
}

func TestUnsafeToggleCompressionSmall(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "server.properties", "network-compression-threshold=16\n")
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonBadValue) {
		t.Fatalf("过小压缩阈值应提示: %v", a.Describe())
	}
}

func TestUnsafeToggleCompressionBad(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "server.properties", "network-compression-threshold=lots\n")
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonBadValue) || !a.Blocking() {
		t.Fatalf("非整数阈值应阻断: %v", a.Describe())
	}
}

func TestUnsafeToggleEarlyWarningBool(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "config/paper-global.yml", "watchdog:\n  early-warning-every: true\n")
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonBadValue) || !a.Blocking() {
		t.Fatalf("布尔预警值应阻断: %v", a.Describe())
	}
}

func TestUnsafeToggleSymlinkConfig(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "pg.yml")
	if err := os.WriteFile(outside, []byte(sunGoodConfig), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "config", "paper-global.yml")); err != nil {
		t.Skipf("symlink 不可用: %v", err)
	}
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonSymlink) || !a.Blocking() {
		t.Fatalf("符号链接应阻断: %v", a.Describe())
	}
}

func TestUnsafeToggleOversize(t *testing.T) {
	dir := t.TempDir()
	sunWriteFile(t, dir, "config/paper-global.yml", sunGoodConfig+strings.Repeat("# padpadding\n", 60000))
	a := AuditServerUnsafeToggles(dir)
	if !sunHas(a.Findings, sunReasonTooLarge) || !a.Blocking() {
		t.Fatalf("超大配置应阻断: %v", a.Describe())
	}
}
