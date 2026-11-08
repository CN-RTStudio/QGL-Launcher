package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sreWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sreHas(a *RconExposureAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestRconExposureClean(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-rcon=false\nenable-query=false\nenable-status=true\nbroadcast-rcon-to-ops=false\n")
	a := AuditServerRconExposure(dir)
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

func TestRconExposureMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestRconExposureEmptyDir(t *testing.T) {
	a := AuditServerRconExposure("")
	if !sreHas(a, sreMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestRconExposureEnabled(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-rcon=true\nrcon.password=supersecretpass\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreRconOn) {
		t.Fatalf("启用 RCON 应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("启用 RCON 应阻断: %v", a.Describe())
	}
}

func TestRconExposureEmptyPassword(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-rcon=true\nrcon.password=\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreRconPass) {
		t.Fatalf("空密码应记录: %v", a.Describe())
	}
}

func TestRconExposureWeakPassword(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-rcon=true\nrcon.password=abc123\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreRconPass) {
		t.Fatalf("弱密码应提示: %v", a.Describe())
	}
}

func TestRconExposureDefaultPassword(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-rcon=true\nrcon.password=minecraft\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreRconDefault) {
		t.Fatalf("默认密码应阻断: %v", a.Describe())
	}
}

func TestRconExposureBroadcast(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "broadcast-rcon-to-ops=true\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreRconBroad) {
		t.Fatalf("广播 RCON 输出应提示: %v", a.Describe())
	}
}

func TestRconExposureQueryEnabled(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-query=true\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreQueryOn) {
		t.Fatalf("启用查询应提示: %v", a.Describe())
	}
}

func TestRconExposureQueryPortInvalid(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-query=true\nquery-port=70000\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreQueryPort) {
		t.Fatalf("非法端口应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("非法端口应阻断: %v", a.Describe())
	}
}

func TestRconExposureStatusDisabled(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-status=false\n")
	a := AuditServerRconExposure(dir)
	if !sreHas(a, sreStatusOff) {
		t.Fatalf("关闭状态应提示: %v", a.Describe())
	}
}

func TestRconExposureBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "\ufeffenable-rcon=\"false\"\nquery-port=\"25577\"\n")
	a := AuditServerRconExposure(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}

func TestRconExposureMultipleSorted(t *testing.T) {
	dir := t.TempDir()
	sreWrite(t, dir, "enable-rcon=true\nrcon.password=minecraft\nbroadcast-rcon-to-ops=true\nenable-query=true\n")
	a := AuditServerRconExposure(dir)
	if len(a.Findings) != 4 {
		t.Fatalf("应有 4 条发现: %v", a.Describe())
	}
}
