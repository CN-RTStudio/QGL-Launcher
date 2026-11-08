package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestApplySanitizedJVMEnv_StripsInjection 校验所有“拉起外部 java 进程”的入口
// 统一经 applySanitizedJVMEnv 净化后，隐式 JVM 参数环境变量不会再泄露给子进程，
// 同时 extra 覆盖仍然生效，并产生审计留痕。
func TestApplySanitizedJVMEnv_StripsInjection(t *testing.T) {
	t.Setenv("JAVA_TOOL_OPTIONS", "-javaagent:C:\\evil.jar")
	t.Setenv("_JAVA_OPTIONS", "-agentpath:bad.dll")
	t.Setenv("CLASSPATH", "C:\\injected")

	cmd := exec.Command("java", "-version")
	app := &App{}
	app.applySanitizedJVMEnv(cmd, "UnitTest", map[string]string{"APPDATA": `C:\sanitized\appdata`})

	var sawInjection, sawClasspath, sawAppdataOverride bool
	for _, entry := range cmd.Env {
		key, _, ok := splitEnvironEntry(entry)
		if !ok {
			t.Fatalf("子进程环境出现非法条目: %q", entry)
		}
		upper := strings.ToUpper(strings.TrimSpace(key))
		switch upper {
		case "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
			"_JPI_VM_OPTIONS", "IBM_JAVA_OPTIONS", "JAVA_VM_OPTIONS":
			sawInjection = true
		case "CLASSPATH":
			sawClasspath = true
		case "APPDATA":
			if entry == `APPDATA=C:\sanitized\appdata` {
				sawAppdataOverride = true
			}
		}
	}
	if sawInjection {
		t.Fatal("净化后的环境仍包含隐式 JVM 参数变量")
	}
	if sawClasspath {
		t.Fatal("净化后的环境仍包含 CLASSPATH")
	}
	if !sawAppdataOverride {
		t.Fatal("extra 覆盖的 APPDATA 未生效")
	}

	events := snapshotSecurityEvents(auditCategoryJVMEnv, 10)
	found := false
	for _, ev := range events {
		if strings.Contains(ev.Detail, "UnitTest") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("剥离 JVM 注入环境变量后未记录安全审计事件")
	}
}
