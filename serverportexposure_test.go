package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProps(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(body), 0o600); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}
}

func TestAuditServerPortExposureDefaults(t *testing.T) {
	dir := t.TempDir()
	writeProps(t, dir, "motd=hello\n")
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() {
		t.Fatalf("默认端口不应阻断: %s", audit.Describe())
	}
	if audit.Ports["server-port"] != defaultServerPort {
		t.Fatalf("应记录默认端口")
	}
}

func TestAuditServerPortExposureConflict(t *testing.T) {
	dir := t.TempDir()
	writeProps(t, dir, "server-port=25566\nenable-query=true\nquery.port=25566\n")
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), portReasonConflict) {
		t.Fatalf("端口冲突应阻断: %s", audit.Describe())
	}
}

func TestAuditServerPortExposureOutOfRange(t *testing.T) {
	dir := t.TempDir()
	writeProps(t, dir, "server-port=70000\n")
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), portReasonOutOfRange) {
		t.Fatalf("越界端口应阻断: %s", audit.Describe())
	}
}

func TestAuditServerPortExposureBadNumber(t *testing.T) {
	dir := t.TempDir()
	writeProps(t, dir, "rcon.port=abc\nenable-rcon=true\n")
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), portReasonBadNumber) {
		t.Fatalf("非数字端口应报告: %v", audit.Codes())
	}
}

func TestAuditServerPortExposurePrivileged(t *testing.T) {
	dir := t.TempDir()
	writeProps(t, dir, "server-port=255\n")
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), portReasonPrivileged) {
		t.Fatalf("特权端口应告警不阻断: %s", audit.Describe())
	}
}

func TestAuditServerPortExposureDisabledPort(t *testing.T) {
	dir := t.TempDir()
	writeProps(t, dir, "enable-rcon=false\nrcon.port=25599\n")
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || !strings.Contains(strings.Join(audit.Codes(), ","), portReasonDisabledPort) {
		t.Fatalf("未启用却配置端口应告警: %s", audit.Describe())
	}
}

func TestAuditServerPortExposureSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "server.properties")
	if err := os.WriteFile(outside, []byte("server-port=25565\n"), 0o600); err != nil {
		t.Fatalf("写入外部配置失败: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "server.properties")); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditServerPortExposure(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接配置应阻断: %s", audit.Describe())
	}
}

func TestAuditServerPortExposureMissing(t *testing.T) {
	audit, err := AuditServerPortExposure(t.TempDir())
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Present || audit.Blocking() || len(audit.Findings) == 0 {
		t.Fatalf("缺失配置应告警不阻断")
	}
}
