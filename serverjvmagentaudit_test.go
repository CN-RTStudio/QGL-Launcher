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

func TestAuditServerJVMAgentsAgentLib(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -agentlib:instrument=foo -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !jaHas(audit, jaReasonAgentLib) {
		t.Fatalf("agentlib 未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("普通 agentlib 只应告警")
	}
}

func TestAuditServerJVMAgentsBootClasspath(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -Xbootclasspath/a:patch.jar -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !audit.Blocking() || !jaHas(audit, jaReasonBootClasspath) {
		t.Fatalf("引导类路径覆盖未阻断: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsJMX(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -Dcom.sun.management.jmxremote.authenticate=false -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !audit.Blocking() || !jaHas(audit, jaReasonJMXOpen) {
		t.Fatalf("JMX 免认证未阻断: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsJMXPort(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "user_jvm_args.txt", "-Dcom.sun.management.jmxremote.port=9010\n")
	audit := AuditServerJVMAgents(dir)
	if !jaHas(audit, jaReasonJMXOpen) {
		t.Fatalf("JMX 端口未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("JMX 端口只应告警")
	}
}

func TestAuditServerJVMAgentsSecurityManager(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "java -Djava.security.manager=allow -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !jaHas(audit, jaReasonSecurityMgr) {
		t.Fatalf("安全管理器允许项未检出: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsSymlinkScript(t *testing.T) {
	dir := t.TempDir()
	target := jaWrite(t, dir, "real-start.sh", "java -jar server.jar\n")
	if err := os.Symlink(target, filepath.Join(dir, "start.sh")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	audit := AuditServerJVMAgents(dir)
	if !audit.Blocking() || !jaHas(audit, jaReasonSymlink) {
		t.Fatalf("符号链接脚本未阻断: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsSymlinkAgent(t *testing.T) {
	dir := t.TempDir()
	target := jaWrite(t, dir, "real-agent.jar", "jar")
	if err := os.Symlink(target, filepath.Join(dir, "agent.jar")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	jaWrite(t, dir, "start.sh", "java -javaagent:agent.jar -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if !jaHas(audit, jaReasonSymlink) {
		t.Fatalf("代理符号链接未检出: %s", audit.Describe())
	}
}

func TestAuditServerJVMAgentsCommentSkipped(t *testing.T) {
	dir := t.TempDir()
	jaWrite(t, dir, "start.sh", "# java -javaagent:/opt/evil.jar\njava -jar server.jar\n")
	audit := AuditServerJVMAgents(dir)
	if audit.Blocking() {
		t.Fatalf("注释行被误判: %s", audit.Describe())
	}
}

func TestjaSplitTokens(t *testing.T) {
	tokens := jaSplitTokens(`java "-javaagent:a b.jar" -jar x.jar`)
	if len(tokens) != 3 {
		t.Fatalf("分词错误: %v", tokens)
	}
	if tokens[1] != "-javaagent:a b.jar" {
		t.Fatalf("引号处理错误: %v", tokens)
	}
}
