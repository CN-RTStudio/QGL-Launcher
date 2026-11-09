package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDatapack(t *testing.T, dir, name string, entries ...string) {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		w, err := writer.Create(entry)
		if err != nil {
			t.Fatalf("创建条目失败: %v", err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatalf("写入条目失败: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("关闭 ZIP 失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o600); err != nil {
		t.Fatalf("写入数据包失败: %v", err)
	}
}

func TestAuditWorldDatapacksClean(t *testing.T) {
	world := t.TempDir()
	dir := filepath.Join(world, "datapacks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	writeDatapack(t, dir, "pack.zip", "pack.mcmeta", "data/x/function/a.mcfunction")
	audit, err := AuditWorldDatapacks(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
		t.Fatalf("unreachable")
	}
	if audit.Blocking() || audit.Packs != 1 || len(audit.Findings) != 0 {
		t.Fatalf("干净数据包不应告警: %+v", audit)
	}
	if !strings.Contains(audit.Describe(), "未发现风险项") {
		t.Fatalf("描述不符")
	}
}

func TestAuditWorldDatapacksMissing(t *testing.T) {
	audit, err := AuditWorldDatapacks(t.TempDir())
	if err != nil || audit.Present || audit.Blocking() {
		t.Fatalf("缺少目录应静默通过: %+v %v", audit, err)
	}
}

func TestAuditWorldDatapacksRejectsTraversalZip(t *testing.T) {
	world := t.TempDir()
	dir := filepath.Join(world, "datapacks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	writeDatapack(t, dir, "evil.zip", "../../evil.mcfunction")
	audit, err := AuditWorldDatapacks(world)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if !audit.Blocking() {
		t.Fatalf("越界条目应阻断: %+v", audit)
	}
	if !strings.Contains(audit.Describe(), "evil.zip") {
		t.Fatalf("描述缺少文件名: %s", audit.Describe())
	}
}

func TestAuditWorldDatapacksRejectsSymlinkPack(t *testing.T) {
	world := t.TempDir()
	dir := filepath.Join(world, "datapacks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
		t.Fatalf("unreachable")
	}
	target := filepath.Join(world, "outside.zip")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.zip")); err != nil {
		t.Skipf("平台不支持符号链接: %v", err)
	}
	audit, err := AuditWorldDatapacks(world)
	if err != nil || !audit.Blocking() {
		t.Fatalf("符号链接数据包应阻断: %+v %v", audit, err)
	}
}

func TestAuditWorldDatapacksRejectsCorruptZip(t *testing.T) {
	world := t.TempDir()
	dir := filepath.Join(world, "datapacks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.zip"), []byte("not a zip"), 0o600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	audit, err := AuditWorldDatapacks(world)
	if err != nil || !audit.Blocking() {
		t.Fatalf("损坏 ZIP 应阻断: %+v %v", audit, err)
	}
}

func TestAuditWorldDatapacksIgnoresNonZipFile(t *testing.T) {
	world := t.TempDir()
	dir := filepath.Join(world, "datapacks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	audit, err := AuditWorldDatapacks(world)
	if err != nil || audit.Blocking() || len(audit.Findings) != 1 {
		t.Fatalf("非 zip 文件仅告警: %+v %v", audit, err)
	}
}
