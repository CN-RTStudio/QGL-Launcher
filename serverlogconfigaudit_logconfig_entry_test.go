package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditServerLogConfigRemoteAppender(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "config/log4j2.xml", "<Configuration><Socket host=\"10.0.0.9\" port=\"4560\"/></Configuration>")
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonRemoteAppender) {
		t.Fatalf("远程 appender 未检出: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigJDBCTarget(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "config/logback.xml", "<appender class=\"JDBCAppender\"><url>jdbc:postgresql://db/log</url></appender>")
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonJDBCTarget) {
		t.Fatalf("JDBC 目标未检出: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigSymlink(t *testing.T) {
	dir := t.TempDir()
	target := lgWriteFile(t, dir, "real.xml", "<Configuration/>")
	link := filepath.Join(dir, "log4j2.xml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("平台不支持符号链接")
	}
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonSymlink) {
		t.Fatalf("符号链接未检出: %s", audit.Describe())
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接配置应阻断")
	}
}

func TestAuditServerLogConfigLogDirSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(t.TempDir(), "real-logs")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "logs")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonLogSymlink) {
		t.Fatalf("日志目录符号链接未检出: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigWorldReadableLog(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "logs/2026-01-01-1.log.gz", "x")
	path := filepath.Join(dir, "logs/2026-01-01-1.log.gz")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonWorldReadable) {
		t.Fatalf("日志全局可读未检出: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigTooManyFiles(t *testing.T) {
	dir := t.TempDir()
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for i := 0; i < lgMaxLogFiles+5; i++ {
		name := filepath.Join(logs, fmt.Sprintf("2026-01-01-%03d.log", i))
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	audit := AuditServerLogConfig(dir)
	if !lgHasReason(audit, lgReasonLogVolume) {
		t.Fatalf("日志数量预算未触发: %s", audit.Describe())
	}
}

func TestAuditServerLogConfigOversized(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过超大文件用例")
	}
	a := LogConfigAudit{Dir: t.TempDir()}
	data := strings.Repeat("a", 16)
	if jndi, _, _, _, _ := lgScanConfigText(data); jndi {
		t.Fatalf("普通文本误判 JNDI")
	}
	if _, lookup, _, _, _ := lgScanConfigText("${sys:user.home}"); !lookup {
		t.Fatalf("sys 查找未识别")
	}
	if a.Blocking() {
		t.Fatalf("空审计不应阻断")
	}
}

func TestAuditServerLogConfigDescribe(t *testing.T) {
	dir := t.TempDir()
	lgWriteFile(t, dir, "log4j2.xml", "<Configuration>${jndi:ldap://x}</Configuration>")
	audit := AuditServerLogConfig(dir)
	if !strings.Contains(audit.Describe(), lgReasonJNDILookup) {
		t.Fatalf("描述缺少 JNDI 原因: %s", audit.Describe())
	}
	if !strings.Contains(audit.Describe(), "log4j2.xml") {
		t.Fatalf("描述缺少文件名: %s", audit.Describe())
	}
}
