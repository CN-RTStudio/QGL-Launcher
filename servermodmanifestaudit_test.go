package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeModJarFixture(t *testing.T, dir, name string, entries map[string]string) string {
	t.Helper()
	target := filepath.Join(dir, name)
	file, err := os.Create(target)
	if err != nil {
		t.Fatalf("创建 jar 失败: %v", err)
	}
	writer := zip.NewWriter(file)
	for entryName, body := range entries {
		entry, err := writer.Create(entryName)
		if err != nil {
			t.Fatalf("写入条目失败: %v", err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatalf("写入条目内容失败: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 zip 失败: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("关闭文件失败: %v", err)
	}
	return target
}

func TestAuditServerModManifestClean(t *testing.T) {
	dir := t.TempDir()
	mods := filepath.Join(dir, "mods")
	if err := os.Mkdir(mods, 0o700); err != nil {
		t.Fatalf("创建 mods 失败: %v", err)
	}
	writeModJarFixture(t, mods, "sodium.jar", map[string]string{
		"fabric.mod.json": `{"id":"sodium","version":"1.0"}`,
		"assets/a.txt":    "ok",
	})
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || len(audit.Findings) != 0 {
		t.Fatalf("干净模组不应有问题: %s", audit.Describe())
	}
	if audit.Jars != 1 {
		t.Fatalf("应统计到 1 个 jar")
	}
}

func TestAuditServerModManifestSuspiciousEntry(t *testing.T) {
	mods := t.TempDir()
	writeModJarFixture(t, mods, "evil.jar", map[string]string{
		"../../startup.jar": "x",
	})
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("路径穿越条目应阻断: %s", audit.Describe())
	}
}

func TestAuditServerModManifestDuplicateModID(t *testing.T) {
	mods := t.TempDir()
	body := `{"id":"sameid"}`
	writeModJarFixture(t, mods, "a.jar", map[string]string{"fabric.mod.json": body})
	writeModJarFixture(t, mods, "b.jar", map[string]string{"fabric.mod.json": body})
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	found := false
	for _, finding := range audit.Findings {
		if finding.Reason == modManifestReasonDuplicateID {
			found = true
		}
	}
	if !found {
		t.Fatalf("重复模组 id 应报告: %s", audit.Describe())
	}
}

func TestAuditServerModManifestBadZip(t *testing.T) {
	mods := t.TempDir()
	target := filepath.Join(mods, "broken.jar")
	if err := os.WriteFile(target, []byte("not a zip"), 0o600); err != nil {
		t.Fatalf("写入坏 jar 失败: %v", err)
	}
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("坏 zip 应阻断: %s", audit.Describe())
	}
}

func TestAuditServerModManifestSymlink(t *testing.T) {
	mods := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.jar")
	writeModJarFixture(t, filepath.Dir(outside), "outside.jar", map[string]string{"a.txt": "x"})
	if err := os.Symlink(outside, filepath.Join(mods, "linked.jar")); err != nil {
		t.Skipf("创建符号链接失败: %v", err)
	}
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("符号链接 jar 应阻断: %s", audit.Describe())
	}
}

func TestAuditServerModManifestMissingDir(t *testing.T) {
	audit, err := AuditServerModManifest(filepath.Join(t.TempDir(), "mods"))
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Present || audit.Blocking() {
		t.Fatalf("缺失 mods 目录应按空处理")
	}
}

func TestAuditServerModManifestDisabledJarSkipped(t *testing.T) {
	mods := t.TempDir()
	if err := os.WriteFile(filepath.Join(mods, "old.jar.disabled"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("写入禁用 jar 失败: %v", err)
	}
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if audit.Blocking() || audit.Jars != 0 {
		t.Fatalf("禁用条目不应参与扫描: %s", audit.Describe())
	}
}

func TestAuditServerModManifestDuplicateEntry(t *testing.T) {
	mods := t.TempDir()
	target := filepath.Join(mods, "dup.jar")
	file, err := os.Create(target)
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	writer := zip.NewWriter(file)
	for _, name := range []string{"x.txt", "x.txt"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatalf("创建条目失败: %v", err)
		}
		entry.Write([]byte("data"))
	}
	writer.Close()
	file.Close()
	audit, err := AuditServerModManifest(mods)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !strings.Contains(strings.Join(audit.Codes(), ","), modManifestReasonDuplicateEntry) {
		t.Fatalf("重复条目应报告: %v", audit.Codes())
	}
}
