package main

import (
	"testing"
)

func TestOnlineModeClean(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "online-mode=true\nenforce-secure-profile=true\nprevent-proxy-connections=true\nnetwork-compression-threshold=256\n")
	if a := AuditServerOnlineMode(dir); a.HasWarnings() {
		t.Fatalf("安全配置不应报警: %v", a.Describe())
	}
}

func TestOnlineModeOffline(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "online-mode=false\n")
	a := AuditServerOnlineMode(dir)
	if !a.Blocking() || !auditHasReason(a, snmOffline) {
		t.Fatalf("离线模式应阻断: %v", a.Describe())
	}
}

func TestOnlineModeSecureProfile(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "online-mode=true\nenforce-secure-profile=false\n")
	a := AuditServerOnlineMode(dir)
	if !auditHasReason(a, snmSecureOff) {
		t.Fatalf("应提示签名校验关闭: %v", a.Describe())
	}
}

func TestOnlineModeCompressionDisabled(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "online-mode=true\nnetwork-compression-threshold=-1\n")
	a := AuditServerOnlineMode(dir)
	if !auditHasReason(a, snmCompressOff) {
		t.Fatalf("应提示压缩关闭: %v", a.Describe())
	}
}

func TestOnlineModeCompressionTooLow(t *testing.T) {
	dir := t.TempDir()
	auditWriteFileInto(t, dir, "online-mode=true\nnetwork-compression-threshold=32\n")
	a := AuditServerOnlineMode(dir)
	if !auditHasReason(a, snmCompressLow) {
		t.Fatalf("应提示阈值过低: %v", a.Describe())
	}
}

func TestOnlineModeMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerOnlineMode(dir)
	if a.Blocking() || !auditHasReason(a, snmMiss) {
		t.Fatalf("缺文件应仅提示: %v", a.Describe())
	}
}
