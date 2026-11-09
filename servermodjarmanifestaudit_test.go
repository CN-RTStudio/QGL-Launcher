package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func mjmWriteJar(t *testing.T, dir, name string, manifest string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "mods"), 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	path := filepath.Join(dir, "mods", name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建 JAR 失败: %v", err)
	}
	writer := zip.NewWriter(file)
	if manifest != "" {
		entry, werr := writer.Create("META-INF/MANIFEST.MF")
		if werr != nil {
			t.Fatalf("写入清单失败: %v", werr)
		}
		if _, werr := entry.Write([]byte(manifest)); werr != nil {
			t.Fatalf("写入清单内容失败: %v", werr)
		}
	}
	if werr := writer.Close(); werr != nil {
		t.Fatalf("关闭 ZIP 失败: %v", werr)
	}
	file.Close()
}

func mjmHasReason(a *ModJarManifestAudit, reason string) bool {
	for _, f := range a.Findings {
		if f.Reason == reason {
			return true
		}
	}
	return false
}

func TestModJarMissing(t *testing.T) {
	a := AuditModJarManifests(t.TempDir())
	if a.Blocking() {
		t.Fatalf("无 mods 不应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonMissing) {
		t.Fatalf("应报告缺少 mods: %s", a.Describe())
	}
}

func TestModJarAgentClass(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "evil.jar", "Manifest-Version: 1.0\r\nPremain-Class: com.example.Agent\r\n")
	a := AuditModJarManifests(dir)
	if !a.Blocking() {
		t.Fatalf("Premain-Class 应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonAgent) {
		t.Fatalf("应报告 agent 类: %s", a.Describe())
	}
	if a.Jars != 1 {
		t.Fatalf("应统计 1 个 JAR, 实际 %d", a.Jars)
	}
}

func TestModJarLauncherAgent(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "launcher.jar", "Manifest-Version: 1.0\r\nLauncher-Agent-Class: boot.Hook\r\n")
	a := AuditModJarManifests(dir)
	if !a.Blocking() {
		t.Fatalf("Launcher-Agent-Class 应阻断: %s", a.Describe())
	}
}

func TestModJarAgentClassContinuation(t *testing.T) {
	dir := t.TempDir()
	manifest := "Manifest-Version: 1.0\r\nAgent-Class: com.example.SomeVeryLongPackageNameForTesting.Tail\r\n"
	mjmWriteJar(t, dir, "cont.jar", manifest)
	a := AuditModJarManifests(dir)
	if !a.Blocking() {
		t.Fatalf("Agent-Class 应阻断: %s", a.Describe())
	}
}

func TestModJarClassPathEscape(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "cp.jar", "Manifest-Version: 1.0\r\nClass-Path: ../../tmp/evil.jar\r\n")
	a := AuditModJarManifests(dir)
	if !a.Blocking() {
		t.Fatalf("Class-Path 越界应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonClassPath) {
		t.Fatalf("应报告 Class-Path: %s", a.Describe())
	}
}

func TestModJarClassPathRemote(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "remote.jar", "Manifest-Version: 1.0\r\nClass-Path: https://example.com/a.jar\r\n")
	a := AuditModJarManifests(dir)
	if !a.Blocking() {
		t.Fatalf("远程 Class-Path 应阻断: %s", a.Describe())
	}
}

func TestModJarClassPathInternal(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "ok.jar", "Manifest-Version: 1.0\r\nClass-Path: libs/dep.class\r\n")
	a := AuditModJarManifests(dir)
	if a.Blocking() {
		t.Fatalf("归档内依赖不应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonClassPath) {
		t.Fatalf("应告警非 META-INF 条目: %s", a.Describe())
	}
}

func TestModJarBadMainClass(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "main.jar", "Manifest-Version: 1.0\r\nMain-Class: ../Boot\r\n")
	a := AuditModJarManifests(dir)
	if a.Blocking() {
		t.Fatalf("非法主类不应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonMainClass) {
		t.Fatalf("应报告非法主类: %s", a.Describe())
	}
}

func TestModJarEmptyManifest(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "empty.jar", "")
	a := AuditModJarManifests(dir)
	if a.Blocking() {
		t.Fatalf("空清单不应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonMissing) {
		t.Fatalf("应报告未发现清单: %s", a.Describe())
	}
}

func TestModJarNotZip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "mods"), 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mods", "broken.jar"), []byte("not a zip"), 0o644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	a := AuditModJarManifests(dir)
	if a.Blocking() {
		t.Fatalf("损坏 JAR 不应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonBadJar) {
		t.Fatalf("应报告损坏 JAR: %s", a.Describe())
	}
}

func TestModJarSymlink(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "real.jar", "Manifest-Version: 1.0\r\n")
	if err := os.Symlink(filepath.Join(dir, "mods", "real.jar"), filepath.Join(dir, "mods", "link.jar")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditModJarManifests(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接 JAR 应阻断: %s", a.Describe())
	}
	if !mjmHasReason(a, mjmReasonSymlink) {
		t.Fatalf("应报告符号链接: %s", a.Describe())
	}
}

func TestModJarServerDirSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "real")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditModJarManifests(link)
	if !a.Blocking() {
		t.Fatalf("服务器目录符号链接应阻断: %s", a.Describe())
	}
}

func TestModJarClean(t *testing.T) {
	dir := t.TempDir()
	mjmWriteJar(t, dir, "clean.jar", "Manifest-Version: 1.0\r\nImplementation-Title: demo\r\n")
	a := AuditModJarManifests(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合规 JAR 不应产生问题: %s", a.Describe())
	}
	if a.Jars != 1 {
		t.Fatalf("应统计 1 个 JAR, 实际 %d", a.Jars)
	}
}
