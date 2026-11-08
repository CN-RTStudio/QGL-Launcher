package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestModNameCollisionKey(t *testing.T) {
	// 这些名字在大小写不敏感 + 尾点 / 尾空格剥除的卷上指向同一文件，键必须相同。
	groups := [][]string{
		{"sodium.jar", "SODIUM.JAR", "Sodium.Jar", "sodium.jar.", "sodium.jar ", "sodium.jar.  "},
		{"mod.jar.disabled", "MOD.JAR.DISABLED", "mod.jar.disabled."},
		{"a", "A", "a.", "a "},
	}
	for _, g := range groups {
		base := modNameCollisionKey(g[0])
		if base == "" {
			t.Fatalf("基准名 %q 键为空", g[0])
		}
		for _, n := range g[1:] {
			if modNameCollisionKey(n) != base {
				t.Errorf("%q 与 %q 应归并为同一碰撞键", g[0], n)
			}
		}
	}
	// 不同名字必须键不同。
	distinct := [][2]string{
		{"a.jar", "b.jar"},
		{"a.jar", "a.zip"},
		{"mod.jar", "mods.jar"},
		{"x.jar", "x.jar.disabled"},
	}
	for _, d := range distinct {
		if modNameCollisionKey(d[0]) == modNameCollisionKey(d[1]) {
			t.Errorf("%q 与 %q 不应碰撞", d[0], d[1])
		}
	}
	// 目录组件必须先剥掉再比较。
	if modNameCollisionKey("dir/sub/a.jar") != modNameCollisionKey("a.jar") {
		t.Error("碰撞键应先剥离目录组件")
	}
}

func TestSplitModStemExt(t *testing.T) {
	cases := []struct {
		name, stem, ext string
	}{
		{"sodium.jar", "sodium", ".jar"},
		{"core.jar.disabled", "core", ".jar.disabled"},
		{"mod.zip", "mod", ".zip"},
		{"plain", "plain", ""},
		{"a.b.c.jar", "a.b.c", ".jar"},
	}
	for _, c := range cases {
		stem, ext := splitModStemExt(c.name)
		if stem != c.stem || ext != c.ext {
			t.Errorf("splitModStemExt(%q) = %q,%q 期望 %q,%q", c.name, stem, ext, c.stem, c.ext)
		}
	}
}

func TestFindModNameCollision(t *testing.T) {
	existing := []string{"Sodium.jar", "JEI 1.20.1.jar", "core.jar.disabled"}
	if _, hit := findModNameCollision(existing, "sodium.JAR"); !hit {
		t.Error("大小写不同应判为碰撞")
	}
	if _, hit := findModNameCollision(existing, "sodium.jar."); !hit {
		t.Error("尾点剥除后应判为碰撞")
	}
	if _, hit := findModNameCollision(existing, "CORE.JAR.DISABLED"); !hit {
		t.Error("复合扩展名大小写不同应判为碰撞")
	}
	if _, hit := findModNameCollision(existing, "lithium.jar"); hit {
		t.Error("不相关的名字不应判为碰撞")
	}
	if _, hit := findModNameCollision(existing, ""); hit {
		t.Error("空候选名不应误判碰撞")
	}
}

func TestUniquifyModName(t *testing.T) {
	// 无碰撞原样返回。
	if got, hit, ok := uniquifyModName(nil, "a.jar"); !ok || hit || got != "a.jar" {
		t.Fatalf("无碰撞场景异常: %q hit=%v ok=%v", got, hit, ok)
	}
	// 单个碰撞派生 (2)。
	got, hit, ok := uniquifyModName([]string{"sodium.jar"}, "SODIUM.jar")
	if !ok || !hit {
		t.Fatalf("应报告碰撞并成功唯一化, got %q hit=%v ok=%v", got, hit, ok)
	}
	if got != "SODIUM (2).jar" {
		t.Fatalf("期望 SODIUM (2).jar, got %q", got)
	}
	// (2) 也被占用时继续跳到 (3)，且比较仍是大小写不敏感。
	got, hit, ok = uniquifyModName([]string{"a.jar", "A (2).JAR"}, "a.jar")
	if !ok || !hit || got != "a (3).jar" {
		t.Fatalf("应跳过被占用的 (2) 到 (3), got %q hit=%v ok=%v", got, hit, ok)
	}
	// 复合扩展名序号插在 .jar.disabled 之前；扩展名大小写按原名保留（NTFS 下等价，
	// 唯一化不应擅自改写调用方给定的大小写）。
	got, _, ok = uniquifyModName([]string{"c.jar.disabled"}, "C.JAR.DISABLED")
	if !ok || got != "C (2).JAR.DISABLED" {
		t.Fatalf("复合扩展名唯一化位置错误, got %q", got)
	}
	// 尾点 / 尾空格等价也会撞。
	got, hit, ok = uniquifyModName([]string{"mod.jar "}, "mod.jar.")
	if !ok || !hit {
		t.Fatalf("尾点尾空格等价应判碰撞, got %q hit=%v", got, hit)
	}
}

func TestPlanModDestNameWithRealDir(t *testing.T) {
	dir := t.TempDir()
	// 预置一个大写名字的旧 jar，模拟目录里已有的未验证文件。
	if err := os.WriteFile(filepath.Join(dir, "Sodium.jar"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 目录不存在的情形：新建一个不存在的子目录，plan 应返回空列表（不报错）。
	missing := filepath.Join(dir, "nope")
	if got, hit, err := planModDestName(missing, "x.jar"); err != nil || hit || got != "x.jar" {
		t.Fatalf("不存在目录应视为无碰撞: %q hit=%v err=%v", got, hit, err)
	}
	// 真实目录里大小写碰撞，必须改名避让而不是复用旧文件。
	final, hit, err := planModDestName(dir, "sodium.jar")
	if err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Error("应检测到与现存 Sodium.jar 的碰撞")
	}
	if final == "sodium.jar" {
		t.Fatalf("碰撞时不能复用原文件名, got %q", final)
	}
	if _, statErr := os.Stat(filepath.Join(dir, final)); !os.IsNotExist(statErr) {
		t.Fatalf("planModDestName 不应创建文件, %q 却已存在", final)
	}
	// 空目录无碰撞。
	empty := t.TempDir()
	if got, hit, err := planModDestName(empty, "jei.jar"); err != nil || hit || got != "jei.jar" {
		t.Fatalf("空目录唯一化异常: %q hit=%v err=%v", got, hit, err)
	}
}

func TestItoaModName(t *testing.T) {
	cases := map[int]string{0: "0", 1: "1", 9: "9", 10: "10", 123: "123", 10000: "10000"}
	for n, want := range cases {
		if got := itoaModName(n); got != want {
			t.Errorf("itoaModName(%d) = %q, 期望 %q", n, got, want)
		}
	}
}
