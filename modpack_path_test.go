package main

// modpack_path_test.go —— 锁定整合包路径处理使用的规范 SafeJoin（sanitize.go）
// 的“词法归一化”语义：它把恶意 "../" 段吞掉、把结果收敛到根目录内，而不是报错。
// 旧的私有助手 safeJoin / hasPathTraversalChars 已删除（生产代码零引用，且其
// 前缀式判定不查符号链接），这些用例统一改测 SafeJoin。

import (
	"path/filepath"
	"strings"
	"testing"
)

// joinUnderBase 判断（词法意义上）p 是否仍在 base 之内。
func joinUnderBase(t *testing.T, base, p string) bool {
	t.Helper()
	absBase, err := filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs == absBase || strings.HasPrefix(abs, absBase+string(filepath.Separator))
}

func TestSafeJoinAllowsInside(t *testing.T) {
	base := t.TempDir()
	got, ok := SafeJoin(base, filepath.Join("mods", "fabric.jar"))
	if !ok {
		t.Fatal("base 内的正常路径应放行")
	}
	if !joinUnderBase(t, base, got) {
		t.Fatalf("拼接结果 %q 不在 base %q 内", got, base)
	}
}

// SafeJoin 对 ../ 的策略是“归一化吞掉”：越界段被裁掉，结果仍落在 base 内，
// 绝不允许解析到 base 之外。
func TestSafeJoinNeutralizesParentTraversal(t *testing.T) {
	base := t.TempDir()
	cases := []string{
		filepath.Join("..", "escape.jar"),
		filepath.Join("mods", "..", "..", "escape.jar"),
		filepath.Join("a", "b", "..", "..", "..", "evil"),
		".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "evil",
	}
	for _, rel := range cases {
		got, ok := SafeJoin(base, rel)
		if !ok {
			// 归一化后只要仍能收敛到 base 内即放行；这里不强制要求一定 ok，
			// 但无论如何结果都不能跑出 base。
			continue
		}
		if !joinUnderBase(t, base, got) {
			t.Errorf("SafeJoin(%q)=%q 跳出了 base", rel, got)
		}
	}
}

// 直接退到根之上、归一化后为空的写法必须返回 false（没有可落的具体子路径）。
func TestSafeJoinRejectsEmptyAndRootEscape(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{"", ".", "..", filepath.Join("..", "..")} {
		if got, ok := SafeJoin(base, rel); ok {
			t.Errorf("SafeJoin(%q) 应返回 false，实际 %q", rel, got)
		}
	}
}

func TestSafeJoinNestedNormal(t *testing.T) {
	base := t.TempDir()
	for _, rel := range []string{
		"mods",
		"mods/sodium-fabric.jar",
		"config/sodium/options.json",
		filepath.Join("a", "b", "c.txt"),
	} {
		got, ok := SafeJoin(base, rel)
		if !ok || !joinUnderBase(t, base, got) {
			t.Errorf("正常相对路径 %q 处理异常: got=%q ok=%v", rel, got, ok)
		}
	}
}
