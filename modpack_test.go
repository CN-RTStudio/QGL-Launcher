package main

// modpack_test.go —— SafeJoin（sanitize.go）在“真实文件系统”层面的越界防护：
// 词法拼接之外，PathWithin 会 EvalSymlinks 解析真实路径，挡住借符号链接逃出根目录。

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSafeJoinCannotReachSibling：即使构造出指向兄弟目录的相对路径（../SECRET/..），
// 归一化后也只能落到 base 内部的同名子路径，绝不能解析到真正的兄弟目录。
func TestSafeJoinCannotReachSibling(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "game")
	sibling := filepath.Join(parent, "SECRET")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(base, filepath.Join(sibling, "loot.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := SafeJoin(base, rel)
	if !ok {
		return // 直接拒绝也是安全的
	}
	realSibling, _ := filepath.Abs(sibling)
	realGot, _ := filepath.Abs(got)
	if realGot == filepath.Join(realSibling, "loot.txt") {
		t.Fatalf("通过 %q 访问到了真实兄弟目录: %s", rel, realGot)
	}
	absBase, _ := filepath.Abs(base)
	if realGot != absBase && !hasBasePrefix(realGot, absBase) {
		t.Fatalf("解析结果 %s 跳出了 base %s", realGot, absBase)
	}
}

func hasBasePrefix(p, base string) bool {
	return len(p) > len(base) &&
		p[:len(base)] == base &&
		p[len(base)] == filepath.Separator
}

// TestSafeJoinBlocksSymlinkEscape：base 内一个指向外部目录的符号链接，不能被用来
// 借 "link/evil" 写出根目录。创建符号链接失败（权限不足）时跳过，不因此误判。
func TestSafeJoinBlocksSymlinkEscape(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("当前环境不允许创建符号链接，跳过该用例")
	}
	got, ok := SafeJoin(base, filepath.Join("link", "evil.txt"))
	if ok {
		// 若放行，解析出的真实路径必须仍在 base 内；link 指向 outside，正常应拒绝。
		real, err := filepath.EvalSymlinks(filepath.Dir(got))
		if err == nil {
			absBase, _ := filepath.Abs(base)
			if real != absBase && !hasBasePrefix(real, absBase) {
				t.Fatalf("借符号链接逃出 base: %s -> %s", got, real)
			}
		}
	}
}

// TestSafeJoinNestedAllowed：多层正常路径仍可正常落在 base 内。
func TestSafeJoinNestedAllowed(t *testing.T) {
	base := t.TempDir()
	got, ok := SafeJoin(base, filepath.Join("overrides", "config", "mod.json"))
	if !ok {
		t.Fatal("整合包常见 overrides 路径应放行")
	}
	absBase, _ := filepath.Abs(base)
	absGot, _ := filepath.Abs(got)
	if !hasBasePrefix(absGot, absBase) {
		t.Fatalf("结果 %s 不在 base %s 内", absGot, absBase)
	}
}
