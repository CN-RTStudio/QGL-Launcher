package main

import (
	"os"
	"path/filepath"
	"testing"
)

func rcnWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func rcnHas(a *RconConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestRconConfigClean(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=false\nrcon.port=25575\nenable-query=false\nserver-ip=127.0.0.1\n")
	a := AuditServerRconConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("干净配置不应报警: %v", a.Describe())
	}
	if a.Blocking() {
		t.Fatalf("干净配置不应阻断: %v", a.Describe())
	}
}

func TestRconConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnMiss) {
		t.Fatalf("缺少属性文件应记录: %v", a.Describe())
	}
}

func TestRconConfigEmptyDir(t *testing.T) {
	a := AuditServerRconConfig("")
	if !rcnHas(a, rcnMiss) {
		t.Fatalf("空目录应记录: %v", a.Describe())
	}
}

func TestRconConfigEnabledNoPassword(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=true\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPwEmpty) {
		t.Fatalf("缺少密码应阻断: %v", a.Describe())
	}
	if !a.Blocking() {
		t.Fatalf("缺少密码应阻断: %v", a.Describe())
	}
}

func TestRconConfigBlankPassword(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=true\nrcon.password=\"\"\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPwEmpty) {
		t.Fatalf("空密码应阻断: %v", a.Describe())
	}
}

func TestRconConfigShortPassword(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=true\nrcon.password=abc123\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPwShort) {
		t.Fatalf("短密码应阻断: %v", a.Describe())
	}
}

func TestRconConfigWeakPassword(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=true\nrcon.password=changeme-please\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPwWeak) {
		t.Fatalf("弱口令应阻断: %v", a.Describe())
	}
}

func TestRconConfigStrongPassword(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=true\nrcon.password=Zx9Qw2Lm7Rt4\n")
	a := AuditServerRconConfig(dir)
	if a.Blocking() {
		t.Fatalf("强密码不应阻断: %v", a.Describe())
	}
}

func TestRconConfigBroadcast(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.enabled=true\nrcon.password=Zx9Qw2Lm7Rt4\nbroadcast-rcon-to-ops=true\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnBroadcast) {
		t.Fatalf("广播给 OP 应提示: %v", a.Describe())
	}
}

func TestRconConfigPortInvalid(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.port=80\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPortInvalid) {
		t.Fatalf("端口越界应阻断: %v", a.Describe())
	}
}

func TestRconConfigPortText(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.port=rcon\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPortInvalid) {
		t.Fatalf("非整数端口应阻断: %v", a.Describe())
	}
}

func TestRconConfigPortClash(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "rcon.port=25575\nquery.port=25575\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnPortClash) {
		t.Fatalf("端口冲突应阻断: %v", a.Describe())
	}
}

func TestRconConfigQueryEnabled(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "enable-query=true\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnQueryOn) {
		t.Fatalf("开启查询应提示: %v", a.Describe())
	}
}

func TestRconConfigQueryPortInvalid(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "query.port=0\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnQueryPort) {
		t.Fatalf("查询端口越界应阻断: %v", a.Describe())
	}
}

func TestRconConfigBindAll(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "server-ip=\n")
	a := AuditServerRconConfig(dir)
	if !rcnHas(a, rcnBindAll) {
		t.Fatalf("未指定监听地址应提示: %v", a.Describe())
	}
}

func TestRconConfigBOMAndQuotes(t *testing.T) {
	dir := t.TempDir()
	rcnWrite(t, dir, "\ufeffrcon.enabled=\"false\"\nrcon.port=\"25575\"\n")
	a := AuditServerRconConfig(dir)
	if a.HasWarnings() {
		t.Fatalf("带 BOM 与引号的合法配置不应报警: %v", a.Describe())
	}
}
