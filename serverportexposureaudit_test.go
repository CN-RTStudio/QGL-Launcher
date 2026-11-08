package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pxWriteProps(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write properties: %v", err)
	}
	return dir
}

func pxHasReason(a ServerPortAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAuditServerPortsMissingFile(t *testing.T) {
	audit := AuditServerPorts(t.TempDir())
	if audit.Blocking() {
		t.Fatalf("缺文件不应阻断: %s", audit.Describe())
	}
	if !pxHasReason(audit, pxReasonMissing) {
		t.Fatalf("缺少 missing 原因: %s", audit.Describe())
	}
}

func TestAuditServerPortsHealthy(t *testing.T) {
	dir := pxWriteProps(t, strings.Join([]string{
		"server-ip=127.0.0.1",
		"server-port=25565",
		"enable-rcon=false",
		"enable-query=false",
		"prevent-proxy-connections=true",
	}, "\n"))
	audit := AuditServerPorts(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("健康配置被误报: %s", audit.Describe())
	}
	if audit.Ports["server-port"] != 25565 {
		t.Fatalf("端口解析错误: %v", audit.Ports)
	}
}

func TestAuditServerPortsBindAll(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=\nserver-port=25565\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonBindAll) {
		t.Fatalf("未检出全网卡绑定: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("全网卡绑定只应告警")
	}
}

func TestAuditServerPortsBadPort(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=10.0.0.5\nserver-port=70000\n")
	audit := AuditServerPorts(dir)
	if !audit.Blocking() {
		t.Fatalf("越界端口应阻断: %s", audit.Describe())
	}
	if !pxHasReason(audit, pxReasonBadPort) {
		t.Fatalf("缺少 bad-port: %s", audit.Describe())
	}
}

func TestAuditServerPortsConflict(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=10.0.0.5\nserver-port=25565\nquery.port=25565\nenable-query=true\n")
	audit := AuditServerPorts(dir)
	if !audit.Blocking() {
		t.Fatalf("端口冲突应阻断: %s", audit.Describe())
	}
	if !pxHasReason(audit, pxReasonPortConflict) {
		t.Fatalf("缺少 port-conflict: %s", audit.Describe())
	}
}

func TestAuditServerPortsRconWithoutPassword(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=127.0.0.1\nserver-port=25565\nenable-rcon=true\nrcon.port=25575\n")
	audit := AuditServerPorts(dir)
	if !audit.Blocking() {
		t.Fatalf("rcon 无口令应阻断: %s", audit.Describe())
	}
	if !pxHasReason(audit, pxReasonRconOpen) {
		t.Fatalf("缺少 rcon-without-password: %s", audit.Describe())
	}
}

func TestAuditServerPortsWeakRconPassword(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=127.0.0.1\nserver-port=25565\nenable-rcon=true\nrcon.port=25575\nrcon.password=minecraft\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonWeakPassword) {
		t.Fatalf("弱口令未检出: %s", audit.Describe())
	}
}

func TestAuditServerPortsShortPassword(t *testing.T) {
	if !pxIsWeakPassword("ab12cd") {
		t.Fatalf("短口令应判弱")
	}
	if pxIsWeakPassword("Str0ng-Pass!") {
		t.Fatalf("强口令被误判")
	}
}

func TestAuditServerPortsRconAllInterfaces(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=0.0.0.0\nserver-port=25565\nenable-rcon=true\nrcon.port=25575\nrcon.password=Str0ng-Pass!\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonRconExposed) {
		t.Fatalf("rcon 暴露未检出: %s", audit.Describe())
	}
}

func TestAuditServerPortsStaleSecret(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=127.0.0.1\nserver-port=25565\nenable-rcon=false\nrcon.password=Str0ng-Pass!\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonStaleSecret) {
		t.Fatalf("残留口令未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("残留口令只应告警")
	}
}

func TestAuditServerPortsProxyBypass(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=127.0.0.1\nserver-port=25565\nprevent-proxy-connections=false\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonProxyBypass) {
		t.Fatalf("代理穿透关闭未检出: %s", audit.Describe())
	}
}

func TestpxParsePort(t *testing.T) {
	if port, ok := pxParsePort("25565"); !ok || port != 25565 {
		t.Fatalf("正常端口解析失败")
	}
	if _, ok := pxParsePort("0"); ok {
		t.Fatalf("0 不应合法")
	}
	if _, ok := pxParsePort("abc"); ok {
		t.Fatalf("非数字不应合法")
	}
}

func TestAuditServerPortsLowPortWarning(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=10.0.0.5\nserver-port=80\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonLowPort) {
		t.Fatalf("特权端口未告警: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("特权端口只应告警")
	}
}

func TestAuditServerPortsDescribe(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=\nserver-port=0\n")
	audit := AuditServerPorts(dir)
	if !strings.Contains(audit.Describe(), pxReasonBadPort) {
		t.Fatalf("描述缺少原因: %s", audit.Describe())
	}
	if !strings.Contains(audit.Describe(), "server.properties") {
		t.Fatalf("描述缺少来源: %s", audit.Describe())
	}
}

func TestAuditServerPortsForbiddenPort(t *testing.T) {
	dir := pxWriteProps(t, "server-ip=10.0.0.5\nserver-port=6379\n")
	audit := AuditServerPorts(dir)
	if !pxHasReason(audit, pxReasonPortConflict) {
		t.Fatalf("与常见服务冲突未检出: %s", audit.Describe())
	}
}
