package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsStrictSubdir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "srv", "world"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	ok := []string{
		filepath.Join(root, "srv"),
		filepath.Join(root, "srv", "world"),
		filepath.Join(root, "srv", "..", "srv", "world"),
	}
	for _, p := range ok {
		if !isStrictSubdir(root, p) {
			t.Errorf("expected strict subdir: %q", p)
		}
	}

	bad := []string{
		root, // 根目录本身：绝不允许删除
		filepath.Join(root, ".."),
		filepath.Join(root, "srv", "..", ".."),
		t.TempDir(), // 完全无关的目录
	}
	for _, p := range bad {
		if isStrictSubdir(root, p) {
			t.Errorf("expected NOT strict subdir: %q", p)
		}
	}
}

// 指向根目录外部的符号链接必须被判定为非严格子目录。
func TestIsStrictSubdirSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "loot.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(root, "evil-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}
	if isStrictSubdir(root, link) {
		t.Error("symlink pointing outside root must not be treated as strict subdir")
	}

	// 指向根目录内部的合法链接应放行。
	inner := filepath.Join(root, "real-srv")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	innerLink := filepath.Join(root, "good-link")
	if err := os.Symlink(inner, innerLink); err != nil {
		t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
	}
	if !isStrictSubdir(root, innerLink) {
		t.Error("symlink staying inside root should be allowed")
	}
}
