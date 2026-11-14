package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mpeWriteJar(t *testing.T, dir, name string, entries [][2]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	path := filepath.Join(dir, "plugins", name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("创建 JAR 失败: %v", err)
	}
	writer := zip.NewWriter(file)
	for _, entry := range entries {
		item, werr := writer.Create(entry[0])
		if werr != nil {
			t.Fatalf("创建条目失败: %v", werr)
		}
		if _, werr := item.Write([]byte(entry[1])); werr != nil {
			t.Fatalf("写入条目失败: %v", werr)
		}
	}
	if werr := writer.Close(); werr != nil {
		t.Fatalf("关闭 ZIP 失败: %v", werr)
	}
	file.Close()
}

func TestPluginJarMissing(t *testing.T) {
	a := AuditPluginJarEntries(t.TempDir())
	if a.Blocking() {
		t.Fatalf("无 plugins 不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonMissing) {
		t.Fatalf("应报告缺少 plugins: %s", a.Describe())
	}
}

func TestPluginJarTraversal(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "evil.jar", [][2]string{{"../../evil.class", "x"}})
	a := AuditPluginJarEntries(dir)
	if !a.Blocking() {
		t.Fatalf("越界条目应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonTraversal) {
		t.Fatalf("应报告路径越界: %s", a.Describe())
	}
}

func TestPluginJarAbsoluteEntry(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "abs.jar", [][2]string{{"/etc/passwd", "x"}})
	a := AuditPluginJarEntries(dir)
	if !a.Blocking() {
		t.Fatalf("绝对路径条目应阻断: %s", a.Describe())
	}
}

func TestPluginJarBackslashEntry(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "win.jar", [][2]string{{"..\\..\\boot.ini", "x"}})
	a := AuditPluginJarEntries(dir)
	if !a.Blocking() {
		t.Fatalf("反斜杠条目应阻断: %s", a.Describe())
	}
}

func TestPluginJarDuplicateEntry(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "dup.jar", [][2]string{{"config.yml", "a"}, {"Config.yml", "b"}})
	a := AuditPluginJarEntries(dir)
	if a.Blocking() {
		t.Fatalf("重复条目不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonDuplicate) {
		t.Fatalf("应报告重复条目: %s", a.Describe())
	}
}

func TestPluginJarEntryTooLarge(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "big.jar", [][2]string{{"big.bin", strings.Repeat("a", 1024)}})
	a := AuditPluginJarEntries(dir)
	if a.Blocking() {
		t.Fatalf("普通文件不应阻断: %s", a.Describe())
	}
	if a.Jars != 1 {
		t.Fatalf("应统计 1 个 JAR, 实际 %d", a.Jars)
	}
}

func TestPluginJarNested(t *testing.T) {
	dir := t.TempDir()
	entries := make([][2]string, 0, 12)
	for i := 0; i < 12; i++ {
		entries = append(entries, [2]string{"libs/dep" + string(rune('a'+i)) + ".jar", "x"})
	}
	mpeWriteJar(t, dir, "nested.jar", entries)
	a := AuditPluginJarEntries(dir)
	if a.Blocking() {
		t.Fatalf("内嵌过多不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonNested) {
		t.Fatalf("应报告内嵌 JAR: %s", a.Describe())
	}
}

func TestPluginJarNotZip(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "plugins"), 0o755); err != nil {
		t.Fatalf("准备目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugins", "broken.jar"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	a := AuditPluginJarEntries(dir)
	if a.Blocking() {
		t.Fatalf("损坏 JAR 不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonBadJar) {
		t.Fatalf("应报告损坏 JAR: %s", a.Describe())
	}
}

func TestPluginJarSymlink(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "real.jar", [][2]string{{"plugin.yml", "name: demo"}})
	if err := os.Symlink(filepath.Join(dir, "plugins", "real.jar"), filepath.Join(dir, "plugins", "link.jar")); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	a := AuditPluginJarEntries(dir)
	if !a.Blocking() {
		t.Fatalf("符号链接应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonSymlink) {
		t.Fatalf("应报告符号链接: %s", a.Describe())
	}
}

func TestPluginJarBadName(t *testing.T) {
	dir := t.TempDir()
	longName := strings.Repeat("p", 180) + ".jar"
	mpeWriteJar(t, dir, longName, [][2]string{{"plugin.yml", "name: demo"}})
	a := AuditPluginJarEntries(dir)
	if a.Blocking() {
		t.Fatalf("超长文件名不应阻断: %s", a.Describe())
	}
	if !auditHasReason(a, mpeReasonBadName) {
		t.Fatalf("应报告超长文件名: %s", a.Describe())
	}
}

func TestPluginJarClean(t *testing.T) {
	dir := t.TempDir()
	mpeWriteJar(t, dir, "clean.jar", [][2]string{{"plugin.yml", "name: demo"}, {"com/demo/Main.class", "x"}, {"libs/dep.jar", "x"}})
	a := AuditPluginJarEntries(dir)
	if a.Blocking() || a.HasWarnings() {
		t.Fatalf("合规插件不应产生问题: %s", a.Describe())
	}
	if a.Jars != 1 {
		t.Fatalf("应统计 1 个 JAR, 实际 %d", a.Jars)
	}
}
