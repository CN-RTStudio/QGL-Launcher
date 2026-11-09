package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsSymlinkOrSpecialDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "region")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	special, err := isSymlinkOrSpecial(dir)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if special {
		t.Fatalf("目录不应被判为符号链接或特殊文件: %s", dir)
	}
}

func TestIsSymlinkOrSpecialRegularAndMissing(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "server.properties")
	if err := os.WriteFile(file, []byte("server-port=25565\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if special, err := isSymlinkOrSpecial(file); err != nil || special {
		t.Fatalf("普通文件应放行: special=%v err=%v", special, err)
	}
	if special, err := isSymlinkOrSpecial(filepath.Join(dir, "absent.properties")); err != nil || special {
		t.Fatalf("不存在的路径应放行: special=%v err=%v", special, err)
	}
}

func TestIsSymlinkOrSpecialSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 创建符号链接需要额外权限")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.properties")
	if err := os.WriteFile(target, []byte("server-port=25565\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link.properties")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("无法创建符号链接: %v", err)
	}
	special, err := isSymlinkOrSpecial(link)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !special {
		t.Fatalf("符号链接应被拦截: %s", link)
	}
}
