package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathWithinRootLexical(t *testing.T) {
	root := filepath.Clean("/tmp/game/libraries")
	cases := []struct {
		child string
		want  bool
	}{
		{filepath.Join(root, "a.jar"), true},
		{filepath.Join(root, "com", "x", "y.jar"), true},
		{root, true},
		{filepath.Join(root, "..", "..", "etc", "passwd"), false},
		{filepath.Clean("/tmp/game/librariesX"), false}, // 兄弟目录前缀
		{filepath.Join(root, "..", "libraries2", "a.jar"), false},
	}
	for _, c := range cases {
		if got := PathWithinRoot(c.child, root); got != c.want {
			t.Errorf("PathWithinRoot(%q) = %v, want %v", c.child, got, c.want)
		}
	}
}

func TestPathWithinRootRejectsBadInput(t *testing.T) {
	if PathWithinRoot("a\x00b", "/tmp/game") {
		t.Error("NUL 字节路径必须被拒绝")
	}
	if PathWithinRoot("", "/tmp/game") {
		t.Error("空路径必须被拒绝")
	}
}

func TestPathWithinRootRelativeResolvedToAbs(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "natives")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(mustGetwd(t), filepath.Join(sub, "x.dll"))
	if err != nil {
		t.Fatal(err)
	}
	if !PathWithinRoot(rel, root) {
		t.Errorf("相对路径解析后应在 root 内: %q", rel)
	}
}

func TestResolvedPathWithinRootRealTree(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "bin")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(inner, "java.exe")
	if err := os.WriteFile(target, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := ResolvedPathWithinRoot(target, root); !ok {
		t.Error("真实位于 root 内的文件应通过")
	}
	if _, ok := ResolvedPathWithinRoot(target, filepath.Join(root, "other")); ok {
		t.Error("不存在的 root 应判定不通过")
	}
}

func TestResolvedPathWithinRootSymlinkEscape(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "evil.exe"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "java.exe")
	if err := os.Symlink(filepath.Join(outside, "evil.exe"), link); err != nil {
		t.Skip("当前环境不允许创建符号链接，跳过：" + err.Error())
	}
	if _, ok := ResolvedPathWithinRoot(link, root); ok {
		t.Error("符号链接解析后逃出 root，必须判定不通过")
	}
}

func TestResolvedPathWithinRootNonexistentChild(t *testing.T) {
	root := t.TempDir()
	// child 尚不存在，但父目录真实在 root 内：应通过。
	future := filepath.Join(root, "newdir", "a.jar")
	if _, ok := ResolvedPathWithinRoot(future, root); !ok {
		t.Error("root 内尚不存在的目标应允许（父目录真实在 root 内/词法在 root 内）")
	}
	// 词法逃逸的不存在目标应拒绝。
	esc := filepath.Join(root, "..", "..", "outside.jar")
	if _, ok := ResolvedPathWithinRoot(esc, root); ok {
		t.Error("词法逃逸的不存在目标必须拒绝")
	}
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

func TestSafeMavenRelPath(t *testing.T) {
	good := []string{
		"com/mojang/netty/1.6/netty-1.6.jar",
		"org/lwjgl/lwjgl/3.3.3/lwjgl-3.3.3-natives-windows.jar",
		"a/b_c/1.0-rc1+x86/ok~1.jar",
	}
	for _, s := range good {
		if got := SafeMavenRelPath(s); got != s {
			t.Errorf("合法 Maven 路径被拒或被改写: %q -> %q", s, got)
		}
	}
	bad := []string{
		"",
		"../evil.jar",
		"com/../../evil.jar",
		`com\xxx\evil.jar`,
		"/etc/evil.jar",
		"C:/Windows/evil.jar",
		"com/evil:1.jar",
		"com/evil.jar/../x",
		"com/a b/evil.jar",
		"com/CON/evil.jar",
		"com/evil.jar:",
		"com/evil|.jar",
		"com/nul",
	}
	for _, s := range bad {
		if got := SafeMavenRelPath(s); got != "" {
			t.Errorf("非法 Maven 路径应被拒绝: %q -> %q", s, got)
		}
	}
}

func TestSafeSimpleName(t *testing.T) {
	if SafeSimpleName("1.21.4") != "1.21.4" {
		t.Error("合法资源索引 ID 应通过")
	}
	if SafeSimpleName("24w14a") != "24w14a" {
		t.Error("合法快照 ID 应通过")
	}
	for _, s := range []string{"../x", "a/b", `a\b`, "a:b", "", "x ", "x.", "CON"} {
		if SafeSimpleName(s) != "" {
			t.Errorf("非法简单名应被拒绝: %q", s)
		}
	}
}

func TestIsLowerHex(t *testing.T) {
	if !IsLowerHex("0123456789abcdef0123456789abcdef01234567", 40) {
		t.Error("40 位小写十六进制应通过")
	}
	for _, s := range []string{"", "abc", "0123456789ABCDEF0123456789ABCDEF01234567", "g123456789012345678901234567890123456789", "0123456789abcdef0123456789abcdef0123456"} {
		if IsLowerHex(s, 40) {
			t.Errorf("非法/长度错误的十六进制应被拒绝: %q", s)
		}
	}
	// 短哈希绝不能让调用方的 hash[:2] 越界——这里先保证校验本身失败。
	if IsLowerHex("a", 40) {
		t.Error("长度 1 的“哈希”必须判非法，防止切片越界 panic")
	}
}
