package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPathWithinAllowsNormal 正常的多层路径必须返回相对路径且 ok。
func TestPathWithinAllowsNormal(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "versions", "1.20", "mods"), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "versions", "1.20", "mods", "sodium.jar")
	if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	rel, ok := PathWithin(root, target)
	if !ok {
		t.Fatalf("正常路径被拒绝: %s", target)
	}
	if filepath.IsAbs(rel) {
		t.Fatalf("返回值应为相对路径，得到 %q", rel)
	}
}

// TestPathWithinRootItself root 本身应返回 "."。
func TestPathWithinRootItself(t *testing.T) {
	root := t.TempDir()
	rel, ok := PathWithin(root, root)
	if !ok || rel != "." {
		t.Fatalf("root 自身应返回 (\".\", true)，得到 (%q,%v)", rel, ok)
	}
}

// TestPathWithinBlocksLexicalTraversal 词法 ../ 越界必须拒绝。
func TestPathWithinBlocksLexicalTraversal(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "qgl-escape-"+filepath.Base(root))
	defer os.RemoveAll(outside)
	if err := os.MkdirAll(outside, 0700); err != nil {
		t.Fatal(err)
	}
	attacks := []string{
		filepath.Join(root, "..", filepath.Base(outside), "evil.txt"),
		filepath.Join(root, "a", "..", "..", "evil.txt"),
		root + string(filepath.Separator) + ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "evil",
	}
	for _, p := range attacks {
		if _, ok := PathWithin(root, p); ok {
			t.Errorf("词法越界路径必须被拒绝: %s", p)
		}
	}
}

// TestPathWithinEmpty 空路径必须拒绝。
func TestPathWithinEmpty(t *testing.T) {
	if _, ok := PathWithin(t.TempDir(), ""); ok {
		t.Fatal("空路径必须返回 false")
	}
}

// TestPathWithinBlocksSymlinkEscape root 内的链接指向 root 外时，
// 无论目标文件是否已存在都必须判为越界。
func TestPathWithinBlocksSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	// 在 root 外放一个敏感文件。
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link-out")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("当前环境无权创建符号链接（Windows 可能需要开发者模式/管理员），跳过: %v", err)
	}

	// 1) 链接本身解析后在 root 外 → 拒绝。
	if _, ok := PathWithin(root, link); ok {
		t.Fatal("指向 root 外的符号链接本身必须被拒绝")
	}
	// 2) 通过链接访问已存在的外部文件 → 拒绝。
	if _, ok := PathWithin(root, filepath.Join(link, "secret.txt")); ok {
		t.Fatal("经符号链接访问 root 外已存在文件必须被拒绝")
	}
	// 3) 通过链接访问尚不存在的外部文件（最长存在祖先是链接）→ 也必须拒绝。
	if _, ok := PathWithin(root, filepath.Join(link, "not-yet-created.txt")); ok {
		t.Fatal("经符号链接定位到 root 外的不存在目标也必须被拒绝")
	}
}

// TestPathWithinAllowsInternalSymlink 链接指向 root 内部是合法的（如 mods 别名）。
func TestPathWithinAllowsInternalSymlink(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real-mods")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "mods-link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("无权创建符号链接，跳过: %v", err)
	}
	target := filepath.Join(link, "a.jar")
	if err := os.WriteFile(target, []byte("j"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := PathWithin(root, target); !ok {
		t.Fatal("解析后仍在 root 内的内部符号链接应当放行")
	}
}

// TestSafeJoinBasics 校验拼接与越界拦截。
func TestSafeJoinBasics(t *testing.T) {
	root := t.TempDir()
	full, ok := SafeJoin(root, filepath.Join("a", "b", "c.txt"))
	if !ok {
		t.Fatal("正常相对路径拼接失败")
	}
	if !filepath.IsAbs(full) {
		t.Fatal("SafeJoin 应返回绝对路径")
	}
	if _, ok := SafeJoin(root, "../../evil.txt"); ok {
		t.Fatal("SafeJoin 必须拦截 ../ 越界")
	}
	if _, ok := SafeJoin(root, ""); ok {
		t.Fatal("SafeJoin 必须拒绝空相对路径")
	}
}

// TestSanitizeFilename 危险字符与首尾点/空格必须被清洗。
func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		`a/b:c?d*.txt`: "a_b_c_d_.txt",
		"  name.":      "name",
		"normal.jar":   "normal.jar",
	}
	for in, want := range cases {
		if got := SanitizeFilename(in); got != want {
			t.Errorf("SanitizeFilename(%q)=%q, want %q", in, got, want)
		}
	}
	if got := SanitizeFilename(strings.Repeat("a", 200)); len(got) != 128 {
		t.Errorf("超长文件名应被截断到 128，得到 %d", len(got))
	}
}

// TestValidateModName 版本/mod 名白名单。

// TestValidateURL 只接受 http/https 且长度受限。

// TestSafeExts 扩展名白名单大小写不敏感。

// TestSanitizeFilenameReservedDeviceNames 保留设备名必须加前缀，正常名字不许误伤。

// TestSanitizeFilenameRuneSafeTruncate 截断必须停在 UTF-8 边界，不能把汉字劈成半个。

// TestValidateURLRejectsStructuralBypass 旧实现只比前缀，这些串都会被放行。

// TestSafeJoinRejectsParentAndVolume 逐段校验：任何 ".." 段与盘符/UNC 一律拒绝，
// 但 root 内以两个点开头的正常条目（"..keep_my_mods"）不能误判。

// TestSanitizeFilenameUnicodeSpaces 覆盖不可见空白：U+00A0 / U+2007 / U+3000
// 这类字符在资源管理器里与普通空格等价，却不会被 " ." 的 Trim 处理。
