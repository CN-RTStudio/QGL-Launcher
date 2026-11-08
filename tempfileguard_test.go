package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareTempPathRemovesStaleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.jar.tmp")
	if err := os.WriteFile(path, []byte("half"), 0600); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	now := time.Now()
	if err := os.Chtimes(path, now.Add(-3*time.Hour), now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("调整时间失败: %v", err)
	}
	result, err := prepareTempPath(path, now, staleTempMaxAge)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if !result.Removed || result.Reason != "removed" {
		t.Fatalf("期望清理过期临时文件: %+v", result)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("临时文件仍然存在")
	}
}

func TestPrepareTempPathKeepsFreshFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fresh.tmp")
	if err := os.WriteFile(path, []byte("active"), 0600); err != nil {
		t.Fatalf("写入临时文件失败: %v", err)
	}
	result, err := prepareTempPath(path, time.Now(), staleTempMaxAge)
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Removed || result.Reason != "fresh" {
		t.Fatalf("新临时文件不应被删除: %+v", result)
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatalf("新临时文件被误删: %v", statErr)
	}
}

func TestPrepareTempPathAbsent(t *testing.T) {
	result, err := prepareTempPath(filepath.Join(t.TempDir(), "none.tmp"), time.Now(), staleTempMaxAge)
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Removed || result.Present || result.Reason != "absent" {
		t.Fatalf("不存在的路径应直接返回: %+v", result)
	}
}

func TestPrepareTempPathRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.bin")
	if err := os.WriteFile(real, []byte("x"), 0600); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	link := filepath.Join(dir, "link.tmp")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("当前平台不支持符号链接: %v", err)
	}
	if _, err := prepareTempPath(link, time.Now(), staleTempMaxAge); err == nil {
		t.Fatalf("符号链接临时路径应当报错")
	}
}

func TestPrepareTempPathRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := prepareTempPath(dir, time.Now(), staleTempMaxAge); err == nil {
		t.Fatalf("目录不应被当作临时文件复用")
	}
}

func TestStaleTempPathForKeepsSibling(t *testing.T) {
	got := staleTempPathFor(filepath.Join("root", "1.21-server.jar"))
	if got != filepath.Join("root", ".1.21-server.jar.tmp") {
		t.Fatalf("临时路径不符合预期: %s", got)
	}
}
