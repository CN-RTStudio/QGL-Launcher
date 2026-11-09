package main

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestJaSplitTokens(t *testing.T) {
	tokens := jaSplitTokens(`java "-javaagent:a b.jar" -jar x.jar`)
	if len(tokens) != 3 {
		t.Fatalf("分词错误: %v", tokens)
	}
	if tokens[1] != "-javaagent:a b.jar" {
		t.Fatalf("引号处理错误: %v", tokens)
	}
}
