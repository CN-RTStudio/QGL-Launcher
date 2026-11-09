package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRemoteFixture(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, "server.properties"), []byte(body), 0o600); err != nil {
			t.Fatalf("写入配置失败: %v", err)
		}
	}
	return dir
}

func remoteCodes(audit *ServerRemoteAudit) []string {
	return audit.Codes()
}

func TestAuditServerRemoteAdminClean(t *testing.T) {
	dir := writeRemoteFixture(t, "online-mode=true\nenable-rcon=false\nenable-query=false\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Present || len(audit.Findings) != 0 {
		t.Fatalf("干净配置不应有风险: %v", audit.Describe())
	}
}

func TestAuditServerRemoteAdminMissingFile(t *testing.T) {
	dir := writeRemoteFixture(t, "")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Present || audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("文件缺失时不应报告风险")
	}
}

func TestAuditServerRemoteAdminRconEmptyPassword(t *testing.T) {
	dir := writeRemoteFixture(t, "enable-rcon=true\nrcon.password=\nrcon.port=25575\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("空密码 RCON 应阻断: %v", audit.Describe())
	}
	if codes := remoteCodes(audit); len(codes) == 0 || codes[0] != remoteReasonEmptyPassword {
		t.Fatalf("应报告空密码: %v", codes)
	}
}

func TestAuditServerRemoteAdminRconShortPassword(t *testing.T) {
	dir := writeRemoteFixture(t, "enable-rcon=true\nrcon.password=abc123\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("短密码应阻断: %v", audit.Describe())
	}
	if got := audit.Findings[0].Reason; got != remoteReasonShortPassword {
		t.Fatalf("原因应为短密码，实际 %s", got)
	}
}

func TestAuditServerRemoteAdminRconWeakPassword(t *testing.T) {
	dir := writeRemoteFixture(t, "enable-rcon=true\nrcon.password=password\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("弱口令应阻断: %v", audit.Describe())
	}
	if got := audit.Findings[0].Reason; got != remoteReasonWeakPassword {
		t.Fatalf("原因应为弱口令，实际 %s", got)
	}
}

func TestAuditServerRemoteAdminRconBadPort(t *testing.T) {
	dir := writeRemoteFixture(t, "enable-rcon=true\nrcon.password=Str0ngPassw0rd\nrcon.port=70000\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("端口越界应阻断: %v", audit.Describe())
	}
	if got := audit.Findings[0].Reason; got != remoteReasonBadPort {
		t.Fatalf("原因应为端口非法，实际 %s", got)
	}
}

func TestAuditServerRemoteAdminIdentityWarnings(t *testing.T) {
	dir := writeRemoteFixture(t, "online-mode=false\nwhite-list=true\nenforce-whitelist=false\nprevent-proxy-connections=false\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() {
		t.Fatalf("身份类问题不应阻断启动: %v", audit.Describe())
	}
	joined := strings.Join(audit.Codes(), ",")
	for _, want := range []string{remoteReasonOfflineMode, remoteReasonEnforceOff, remoteReasonProxyBypass} {
		if !strings.Contains(joined, want) {
			t.Fatalf("缺少 %s: %v", want, joined)
		}
	}
}

func TestAuditServerRemoteAdminQueryConflict(t *testing.T) {
	dir := writeRemoteFixture(t, "enable-query=true\nquery.port=25575\nenable-rcon=true\nrcon.password=Str0ngPassw0rd\nrcon.port=25575\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	joined := strings.Join(audit.Codes(), ",")
	if !strings.Contains(joined, remoteReasonQueryOpen) || !strings.Contains(joined, remoteReasonPortConflict) {
		t.Fatalf("应同时报告查询开放与端口冲突: %v", joined)
	}
}

func TestAuditServerRemoteAdminDuplicateKey(t *testing.T) {
	dir := writeRemoteFixture(t, "online-mode=true\nonline-mode=false\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), remoteReasonDuplicateKey) {
		t.Fatalf("重复键应报告: %v", audit.Codes())
	}
}

func TestAuditServerRemoteAdminBindAll(t *testing.T) {
	dir := writeRemoteFixture(t, "server-ip=0.0.0.0\n")
	audit, err := AuditServerRemoteAdmin(dir)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), remoteReasonBindAll) {
		t.Fatalf("通配绑定应报告: %v", audit.Codes())
	}
}
