package main

import (
	"os"
	"path/filepath"
	"testing"
)

func sjaWrite(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "user_jvm_args.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func sjaHas(findings []JvmArgsFinding, reason string) bool {
	for _, f := range findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestJvmArgsClean(t *testing.T) {
	dir := t.TempDir()
	sjaWrite(t, dir, "-Xms4G\n-Xmx8G\n-XX:+UseG1GC\n")
	if a := AuditServerJvmArgsFile(dir); a.HasWarnings() {
		t.Fatalf("合法参数不应报警: %v", a.Describe())
	}
}

func TestJvmArgsAgent(t *testing.T) {
	dir := t.TempDir()
	sjaWrite(t, dir, "-javaagent:C:\\temp\\evil.jar\n-Xmx4G\n")
	a := AuditServerJvmArgsFile(dir)
	if !a.Blocking() || !sjaHas(a.Findings, sjaReasonAgent) {
		t.Fatalf("javaagent 应阻断: %v", a.Describe())
	}
}

func TestJvmArgsOnError(t *testing.T) {
	dir := t.TempDir()
	sjaWrite(t, dir, "-XX:OnOutOfMemoryError=cmd /c calc\n")
	a := AuditServerJvmArgsFile(dir)
	if !a.Blocking() || !sjaHas(a.Findings, sjaReasonExec) {
		t.Fatalf("OnOOM 命令应阻断: %v", a.Describe())
	}
}

func TestJvmArgsHeap(t *testing.T) {
	dir := t.TempDir()
	sjaWrite(t, dir, "-Xmx64G\n")
	a := AuditServerJvmArgsFile(dir)
	if !sjaHas(a.Findings, sjaReasonHeap) {
		t.Fatalf("超大堆应报警: %v", a.Describe())
	}
}

func TestJvmArgsArgfile(t *testing.T) {
	dir := t.TempDir()
	sjaWrite(t, dir, "@C:\\temp\\args.txt\n")
	a := AuditServerJvmArgsFile(dir)
	if !sjaHas(a.Findings, sjaReasonArg) {
		t.Fatalf("argfile 间接应报警: %v", a.Describe())
	}
}
