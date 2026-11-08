package main

import (
	"os"
	"path/filepath"
	"testing"
)

func snmWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func snmHas(a *OnlineModeAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestOnlineModeClean(t *testing.T) {
	dir := t.TempDir()
	snmWrite(t, dir, "online-mode=true\nenforce-secure-profile=true\nprevent-proxy-connections=true\nnetwork-compression-threshold=256\n")
	if a := AuditServerOnlineMode(dir); a.HasWarnings() {
		t.Fatalf("安全配置不应报警: %v", a.Describe())
	}
}

func TestOnlineModeOffline(t *testing.T) {
	dir := t.TempDir()
	snmWrite(t, dir, "online-mode=false\n")
	a := AuditServerOnlineMode(dir)
	if !a.Blocking() || !snmHas(a, snmOffline) {
		t.Fatalf("离线模式应阻断: %v", a.Describe())
	}
}

func TestOnlineModeSecureProfile(t *testing.T) {
	dir := t.TempDir()
	snmWrite(t, dir, "online-mode=true\nenforce-secure-profile=false\n")
	a := AuditServerOnlineMode(dir)
	if !snmHas(a, snmSecureOff) {
		t.Fatalf("应提示签名校验关闭: %v", a.Describe())
	}
}

func TestOnlineModeCompressionDisabled(t *testing.T) {
	dir := t.TempDir()
	snmWrite(t, dir, "online-mode=true\nnetwork-compression-threshold=-1\n")
	a := AuditServerOnlineMode(dir)
	if !snmHas(a, snmCompressOff) {
		t.Fatalf("应提示压缩关闭: %v", a.Describe())
	}
}

func TestOnlineModeCompressionTooLow(t *testing.T) {
	dir := t.TempDir()
	snmWrite(t, dir, "online-mode=true\nnetwork-compression-threshold=32\n")
	a := AuditServerOnlineMode(dir)
	if !snmHas(a, snmCompressLow) {
		t.Fatalf("应提示阈值过低: %v", a.Describe())
	}
}

func TestOnlineModeMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerOnlineMode(dir)
	if a.Blocking() || !snmHas(a, snmMiss) {
		t.Fatalf("缺文件应仅提示: %v", a.Describe())
	}
}
