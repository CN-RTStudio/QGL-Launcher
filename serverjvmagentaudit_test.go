package main

import (
	"os"
	"path/filepath"
	"testing"
)

func jaWrite(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func jaHas(a JVMAgentAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAuditServerJVMAgentsMissing(t *testing.T) {
	audit := AuditServerJVMAgents(t.TempDir())
	if audit.Blocking() {
		t.Fatalf("无启动脚本不应阻断: %s", audit.Describe())
	}
	if !jaHas(audit, jaReasonMissing) {
		t.Fatalf("缺少 missing: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsHealthy(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "#!/bin/sh\njava -Xmx4G -jar server.jar nogui\n")
	audit := AuditServerJVMAgents(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("健康脚本被误报: %s", audit.Describe())
	}
	if len(audit.Scripts) != 1 {
		t.Fatalf("脚本计数错误: %v", audit.Scripts)
	}
}

func TestAuditServerJVMAgentsInsideAgent(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "agent.jar", "jar")
	jaWrite(t, dir, "start.bat", "java -javaagent:agent.jar -jar server.jar nogui\n")
	audit := AuditServerJVMAgents(dir)
	if audit.Blocking() {
		t.Fatalf("目录内代理被误判: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsOutsideAgent(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -javaagent:/opt/evil/agent.jar -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !audit.Blocking() {
		t.Fatalf("目录外代理应阻断: %s", audit.Describe())
	}
	if !jaHas(audit, jaReasonAgentOutside) {
		t.Fatalf("缺少 agent-outside-server: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsTraversalAgent(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -javaagent:../agent.jar -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !jaHas(audit, jaReasonAgentTraversal) {
		t.Fatalf("上级目录代理未检出: %s", audit.Describe())
	}
	if !audit.Blocking() {
		t.Fatalf("上级目录代理应阻断")
	}
}

func TestAuditServerJVMAgentsMissingAgent(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.bat", "java -javaagent:agent.jar -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !jaHas(audit, jaReasonAgentMissing) {
		t.Fatalf("缺失代理未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("缺失代理只应告警")
	}
}

func TestAuditServerJVMAgentsAgentOptions(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "agent.jar", "jar")
	jaWrite(t, dir, "start.sh", "java \"-javaagent:agent.jar=port=8080\" -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if audit.Blocking() {
		t.Fatalf("带选项的目录内代理被误判: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsDebugAgent(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !audit.Blocking() {
		t.Fatalf("JDWP 应阻断: %s", audit.Describe())
	}
	if !jaHas(audit, jaReasonDebugAgent) {
		t.Fatalf("缺少 debug-agent: %s", audit.Describe())
	}
}
