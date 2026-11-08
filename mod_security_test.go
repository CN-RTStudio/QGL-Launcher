package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 目录包含判定已统一收口到 PathWithin（真实符号链接解析），这里验证其词法边界行为
// 与原 isPathInDir 保持一致；符号链接逃逸另有专门用例。
func TestPathWithinContainment(t *testing.T) {
	root := t.TempDir()

	innerFile := filepath.Join(root, "mods", "fabric-api.jar")
	if err := os.MkdirAll(filepath.Dir(innerFile), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(innerFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"root itself", root, true},
		{"nested file", innerFile, true},
		{"nested dir", filepath.Join(root, "mods"), true},
		{"dot segment still inside", filepath.Join(root, "mods", "..", "mods", "a.jar"), true},
		{"parent escape", filepath.Join(root, "..", "evil.jar"), false},
		{"deep parent escape", filepath.Join(root, "mods", "..", "..", "evil.jar"), false},
		{"sibling dir", filepath.Join(filepath.Dir(root), "sibling", "x.jar"), false},
		{"unrelated temp dir", filepath.Join(t.TempDir(), "x.jar"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ok := PathWithin(root, c.path)
			if ok != c.want {
				t.Errorf("PathWithin(%q)=%v want %v", c.path, ok, c.want)
			}
		})
	}
}

// 目录内合法的、仅名字以两个点开头的条目（"..foo"）不应被误判为越界，
// 同时真正的 ".." 父级跳转必须被拦住。
func TestPathWithinDotDotBoundary(t *testing.T) {
	root := t.TempDir()
	dotName := filepath.Join(root, "..keep_my_mods")
	if err := os.MkdirAll(filepath.Join(dotName, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir ..keep: %v", err)
	}
	if _, ok := PathWithin(root, filepath.Join(dotName, "a.jar")); !ok {
		t.Error("legitimate '..keep_my_mods' entry wrongly reported outside root")
	}
	if _, ok := PathWithin(root, filepath.Join(root, "..keep_my_mods", "..", "..", "evil.jar")); ok {
		t.Error("escape through parent segments should be rejected")
	}
}

// 符号链接逃逸：root 内的一个链接指向 root 外真实目录时，纯词法判定会漏判，
// PathWithin 必须在解析链接后识别出目标已越界。Windows 下无创建符号链接权限时跳过。
func TestPathWithinSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	evilFile := filepath.Join(outside, "evil.jar")
	if err := os.WriteFile(evilFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "linkmods")
	if err := os.Symlink(outside, linkDir); err != nil {
		t.Skipf("当前环境不允许创建符号链接，跳过: %v", err)
	}
	// 词法上在 root/linkmods 内，解析链接后落到 outside，必须拒绝。
	if _, ok := PathWithin(root, filepath.Join(linkDir, "evil.jar")); ok {
		t.Fatal("root 内符号链接指向外部时 PathWithin 应拒绝")
	}
	if _, ok := PathWithin(root, linkDir); ok {
		t.Fatal("符号链接目录本身指向外部时也应拒绝")
	}
}

func TestIsValidModID(t *testing.T) {
	valid := []string{"a", "fabric-api", "sodium_1.20", "A-Z_0-9", strings.Repeat("a", 100)}
	for _, id := range valid {
		if !isValidModID(id) {
			t.Errorf("expected valid mod id: %q", id)
		}
	}
	invalid := []string{
		"",
		"../escape",
		"a/b",
		"a.b",
		"has space",
		"a;rm",
		"中文",
		strings.Repeat("a", 101),
	}
	for _, id := range invalid {
		if isValidModID(id) {
			t.Errorf("expected invalid mod id: %q", id)
		}
	}
}

func TestIsValidMCVersion(t *testing.T) {
	valid := []string{"1.20.1", "1_20-1", "1-20_1"}
	for _, v := range valid {
		if !isValidMCVersion(v) {
			t.Errorf("expected valid mc version: %q", v)
		}
	}
	invalid := []string{"1.20.1;rm -rf", "v1.20", "1.20 1", "中", strings.Repeat("1", 21)}
	for _, v := range invalid {
		if isValidMCVersion(v) {
			t.Errorf("expected invalid mc version: %q", v)
		}
	}
}
