package main

// moddirscan_test.go —— mods 目录存量扫描：启用/禁用条目、干净 Mod 放行、
// 高危 jar 标记阻断。

import (
	"os"
	"path/filepath"
	"testing"
)

func writeJar(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestListEnabledJarsSkipsDisabledAndNonJar(t *testing.T) {
	dir := t.TempDir()
	writeJar(t, dir, "a.jar", []byte("x"))
	writeJar(t, dir, "b.jar.disabled", []byte("x"))
	writeJar(t, dir, "notes.txt", []byte("x"))

	jars, skipped, err := listEnabledJars(dir)
	if err != nil {
		t.Fatalf("listEnabledJars: %v", err)
	}
	if len(jars) != 1 {
		t.Fatalf("应只列出 1 个启用 jar，得到 %d: %v", len(jars), jars)
	}
	if filepath.Base(jars[0]) != "a.jar" {
		t.Fatalf("列出的应为 a.jar，得到 %v", jars)
	}
	if skipped != 0 {
		t.Fatalf("未超上限时 skipped 应为 0，得到 %d", skipped)
	}
}

func TestListEnabledJarsMissingDir(t *testing.T) {
	jars, _, err := listEnabledJars(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatalf("目录不存在应返回空而非错误: %v", err)
	}
	if len(jars) != 0 {
		t.Fatalf("目录不存在应无 jar，得到 %v", jars)
	}
}

func TestScanOneInstalledJarClean(t *testing.T) {
	clean := buildJarWithClasses(t, map[string][]byte{
		"fabric.mod.json":  []byte(`{"id":"clean"}`),
		"com/a/Main.class": []byte("CAFEBABE"),
	})
	p := writeJar(t, t.TempDir(), "clean.jar", clean)
	risk := scanOneInstalledJar(p)
	if risk.Blocked {
		t.Fatalf("干净 Mod 不应被标记阻断: %+v", risk)
	}
}

func TestScanOneInstalledJarRootExecBlocked(t *testing.T) {
	malicious := buildJarInMemory(t, map[string]string{
		"evil.exe": "MZ",
	})
	p := writeJar(t, t.TempDir(), "evil.jar", malicious)
	risk := scanOneInstalledJar(p)
	if !risk.Blocked {
		t.Fatalf("根目录 .exe 应被标记阻断: %+v", risk)
	}
	if risk.JarCritical == 0 {
		t.Fatalf("JarCritical 应 > 0: %+v", risk)
	}
	if len(risk.Reasons) == 0 {
		t.Fatalf("阻断时应给出原因: %+v", risk)
	}
}

func TestScanOneInstalledJarLog4ShellBlocked(t *testing.T) {
	malicious := buildJarWithClasses(t, map[string][]byte{
		"org/apache/logging/log4j/core/lookup/JndiLookup.class": []byte("CAFEBABE"),
	})
	p := writeJar(t, t.TempDir(), "log4.jar", malicious)
	risk := scanOneInstalledJar(p)
	if !risk.Blocked {
		t.Fatalf("JndiLookup jar 应被标记阻断: %+v", risk)
	}
	if risk.Log4Critical == 0 {
		t.Fatalf("Log4Critical 应 > 0: %+v", risk)
	}
}

func TestScanOneInstalledJarUnreadable(t *testing.T) {
	p := writeJar(t, t.TempDir(), "broken.jar", []byte("this is not a zip"))
	risk := scanOneInstalledJar(p)
	if !risk.Blocked {
		t.Fatalf("无法解析的 jar 应阻断以防绕过: %+v", risk)
	}
}
