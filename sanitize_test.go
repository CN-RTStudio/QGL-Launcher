package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
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
func TestValidateModName(t *testing.T) {
	good := []string{"1.20.1", "forge-1.20.1-47.2.0", "sodium-fabric_0.5", "A_b-c.1"}
	for _, n := range good {
		if !ValidateModName(n) {
			t.Errorf("合法名称被拒: %q", n)
		}
	}
	bad := []string{"", "../etc", "a b", "a/b", strings.Repeat("a", 65), "name;rm"}
	for _, n := range bad {
		if ValidateModName(n) {
			t.Errorf("非法名称被放行: %q", n)
		}
	}
}

// TestValidateURL 只接受 http/https 且长度受限。
func TestValidateURL(t *testing.T) {
	if !ValidateURL("https://example.com/a") {
		t.Error("https 应放行")
	}
	if !ValidateURL("http://127.0.0.1:8080") {
		t.Error("http 应放行")
	}
	for _, u := range []string{"", "javascript:alert(1)", "file:///c:/x", "ftp://x", strings.Repeat("h", 2049)} {
		if ValidateURL(u) {
			label := u
			if len(label) > 12 {
				label = label[:12]
			}
			t.Errorf("非法 URL 被放行: %q", label)
		}
	}
}

// TestSafeExts 扩展名白名单大小写不敏感。
func TestSafeExts(t *testing.T) {
	if !IsSafeImageExt("a.PNG") || !IsSafeArchiveExt("p.MRPACK") {
		t.Error("扩展名匹配应大小写不敏感")
	}
	if IsSafeImageExt("a.exe") || IsSafeArchiveExt("a.jar") {
		t.Error("非白名单扩展名必须拒绝")
	}
}

// TestSanitizeFilenameReservedDeviceNames 保留设备名必须加前缀，正常名字不许误伤。
func TestSanitizeFilenameReservedDeviceNames(t *testing.T) {
	cases := map[string]string{
		"CON":         "_CON",
		"nul.txt":     "_nul.txt",
		"COM1":        "_COM1",
		"LPT9.log":    "_LPT9.log",
		"console.log": "console.log",
		"auxiliary":   "auxiliary",
	}
	for in, want := range cases {
		if got := SanitizeFilename(in); got != want {
			t.Errorf("SanitizeFilename(%q)=%q, want %q", in, got, want)
		}
	}
}

// TestSanitizeFilenameRuneSafeTruncate 截断必须停在 UTF-8 边界，不能把汉字劈成半个。
func TestSanitizeFilenameRuneSafeTruncate(t *testing.T) {
	long := strings.Repeat("中", 60) // 180 字节，128 字节处正好落在第 43 个字符中间
	got := SanitizeFilename(long)
	if len(got) > 128 {
		t.Errorf("截断后仍超过 128 字节: %d", len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("截断把 UTF-8 字符劈开了: %q", got)
	}
	if strings.Contains(got, string(utf8.RuneError)) {
		t.Errorf("截断结果含替换字符: %q", got)
	}
}

// TestValidateURLRejectsStructuralBypass 旧实现只比前缀，这些串都会被放行。
func TestValidateURLRejectsStructuralBypass(t *testing.T) {
	bad := []string{
		"https://",
		"https:///path-only",
		"https://user:pw@example.com/a.jpg",
		"https://example.com/a b.jpg",
		"https://example.com/\x00.jpg",
		"https://example.com:0/x",
		"https://example.com:70000/x",
		"http:opaque-only",
		"https://:443/x",
	}
	for _, u := range bad {
		if ValidateURL(u) {
			t.Errorf("结构性非法 URL 被放行: %q", u)
		}
	}
	good := []string{
		"https://example.com/a.jpg",
		"HTTPS://EXAMPLE.COM/a.jpg?x=1#frag",
		"http://127.0.0.1:8080/api",
		"https://example.com:8443/x",
	}
	for _, u := range good {
		if !ValidateURL(u) {
			t.Errorf("合法 URL 被拒: %q", u)
		}
	}
}

// TestSafeJoinRejectsParentAndVolume 逐段校验：任何 ".." 段与盘符/UNC 一律拒绝，
// 但 root 内以两个点开头的正常条目（"..keep_my_mods"）不能误判。
func TestSafeJoinRejectsParentAndVolume(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"../evil.txt",
		"a/../../evil.txt",
		`a\..\..\evil.txt`,
		"C:evil.txt",
		`\\server\share\evil.txt`,
		"/abs/evil.txt",
	} {
		if got, ok := SafeJoin(root, rel); ok {
			t.Errorf("SafeJoin(%q) 应拒绝，实际 %q", rel, got)
		}
	}
	for _, rel := range []string{"mods", "mods/./sodium.jar", `versions\1.20\mods`} {
		got, ok := SafeJoin(root, rel)
		if !ok || got == "" {
			t.Errorf("SafeJoin(%q) 应放行", rel)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "..keep_my_mods"), 0o755); err != nil {
		t.Fatalf("mkdir ..keep: %v", err)
	}
	if _, ok := SafeJoin(root, "..keep_my_mods/a.jar"); !ok {
		t.Error("以两个点开头的合法子目录被误拒")
	}
}

// TestSanitizeFilenameUnicodeSpaces 覆盖不可见空白：U+00A0 / U+2007 / U+3000
// 这类字符在资源管理器里与普通空格等价，却不会被 " ." 的 Trim 处理。
func TestSanitizeFilenameUnicodeSpaces(t *testing.T) {
	cases := []struct{ in, want string }{
		{"x\u00a0.jar", "x_.jar"},
		{"x\u3000.exe", "x_.exe"},
		{"x\u2007.pdf", "x_.pdf"},
		{"x\u202f.jar", "x_.jar"},
		{"x\u2009.jar", "x_.jar"},
		{"sodium\u00a0mod.jar", "sodium_mod.jar"},
	}
	for _, c := range cases {
		got := SanitizeFilename(c.in)
		if got != c.want {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", c.in, got, c.want)
		}
		if strings.ContainsAny(got, "\u00a0\u3000\u2007\u202f\u2009") {
			t.Errorf("SanitizeFilename 残留不可见空白: %q", got)
		}
	}
	// 普通空格与下划线不受影响（不能把合法名字改坏）。
	for _, n := range []string{"my mod.jar", "my_mod.jar", "版本 1.20.jar"} {
		if got := SanitizeFilename(n); got != n {
			t.Errorf("SanitizeFilename(%q) = %q, want unchanged", n, got)
		}
	}
}
