package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsModJarName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"fabric-api.jar", true},
		{"fabric-api.JAR", true},
		{"fabric-api.Jar.Disabled", true},
		{"mod.jar.disabled", true},
		{"mod.zip", false},
		{"mod.jar.zip", false},
		{"mod", false},
		{".jar", true},
		{"", false},
		{"..", false},
		{"a.jar ", false},
		{"a.jar.", false},
		{"a\x00.jar", false},
		{"a\nb.jar", false},
		{"dir/a.jar", false},
		{`dir\a.jar`, false},
	}
	for _, c := range cases {
		if got := isModJarName(c.name); got != c.want {
			t.Errorf("isModJarName(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestResolveManagedModPath(t *testing.T) {
	mc := t.TempDir()
	join := filepath.Join

	okPaths := []string{
		join(mc, "mods", "a.jar"),
		join(mc, "mods", "a.jar.disabled"),
		join(mc, "mods", "Big-Mod.JAR"),
		join(mc, "versions", "1.20.1", "mods", "fabric.jar"),
		join(mc, "versions", "1.20.1", "mods", "x.jar.disabled"),
		// versions 段内部带 "." 是正常版本号，应放行。
		join(mc, "versions", "1.20.1-forge-47.2.0", "mods", "m.jar"),
	}
	for _, p := range okPaths {
		got, ok := resolveManagedModPath(mc, p)
		if !ok {
			t.Errorf("expected managed: %s", p)
			continue
		}
		wantAbs, err := canonicalAbs(p)
		if err != nil {
			t.Fatalf("canonicalAbs(%s): %v", p, err)
		}
		if got != wantAbs {
			t.Errorf("resolved %s -> %s, want %s", p, got, wantAbs)
		}
	}

	badPaths := []string{
		// .minecraft 内但不在受管 mods 目录：历史漏洞面（改名库 / 删存档）。
		join(mc, "libraries", "com", "x.jar"),
		join(mc, "versions", "1.20.1", "1.20.1.jar"),
		join(mc, "saves", "world", "level.dat"),
		join(mc, "mods"),                    // mods 目录本身，无文件
		join(mc, "mods", "sub", "a.jar"),    // mods 子目录（UI 不列出，不属受管）
		join(mc, "versions", "1.20", "mods"),                      // 缺文件
		join(mc, "versions", "mods", "a.jar"),                     // 缺版本段
		join(mc, "versions", "1.20", "mods", "sub", "a.jar"),     // 隔离 mods 子目录
		join(mc, "mods", "a.txt"),                                 // 非 jar
		join(mc, "mods", "a.jar.zip"),                             // 伪装双扩展
		join(mc, "mods", "readme"),                                // 无扩展名
		// Clean 折叠后指向外部：必须拒绝。
		join(mc, "mods", "..", "..", "evil.jar"),
		filepath.Join(filepath.Dir(mc), "outside.jar"),
		// 控制字符 / 非法文件名。
		join(mc, "mods", "a\x00.jar"),
		join(mc, "mods", "a.jar "),
		// 空串与根。
		"",
		mc,
	}
	for _, p := range badPaths {
		if _, ok := resolveManagedModPath(mc, p); ok {
			t.Errorf("expected NOT managed: %q", p)
		}
	}
}

func TestResolveManagedModPathLexicalEscapeFolds(t *testing.T) {
	mc := t.TempDir()
	// mods/../mods/a.jar 经 Clean 折叠后确为全局 mods 下的合法 jar，按受管处理，
	// 证明判定基于规范化路径而非脆弱的字符串前缀。
	p := filepath.Join(mc, "versions", "..", "mods", "a.jar")
	got, ok := resolveManagedModPath(mc, p)
	if !ok {
		t.Fatalf("folded path should be managed: %s", p)
	}
	want, _ := canonicalAbs(filepath.Join(mc, "mods", "a.jar"))
	if got != want {
		t.Errorf("folded resolved = %s, want %s", got, want)
	}
}

func TestResolveManagedModPathRejectsRelativeRootJunk(t *testing.T) {
	// 空 / 含 NUL 的 mcDir 直接拒绝，不 panic。
	if _, ok := resolveManagedModPath("", "mods/a.jar"); ok {
		t.Error("empty mcDir must reject")
	}
	if _, ok := resolveManagedModPath("C:\x00bad", "x"); ok {
		t.Error("NUL mcDir must reject")
	}
}

func TestSameManagedModDir(t *testing.T) {
	sep := string(os.PathSeparator)
	cases := []struct {
		from, to string
		want     bool
	}{
		{`C:\mc\mods\a.jar.disabled`, `C:\mc\mods\a.jar`, true},
		{`C:\mc\versions\v1\mods\a.jar.disabled`, `C:\mc\versions\v1\mods\a.jar`, true},
		{`C:\mc\mods\a.jar.disabled`, `C:\mc\versions\v1\mods\a.jar`, false},
		{`C:\mc\mods\a.jar`, `C:\mc\libraries\a.jar`, false},
		{`C:\mc\mods\a.jar`, `C:\mc\mods\sub\a.jar`, false},
	}
	// 反斜杠用例仅在 Windows 成立；其它平台跳过该组（另有跨平台用例）。
	if sep != `\` {
		t.Skip("backslash literal cases only apply on Windows")
	}
	for _, c := range cases {
		if got := sameManagedModDir(c.from, c.to); got != c.want {
			t.Errorf("sameManagedModDir(%q,%q)=%v want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestResolveManagedModsDir(t *testing.T) {
	mc := t.TempDir()
	join := filepath.Join

	okDirs := []string{
		join(mc, "mods"),
		join(mc, "versions", "1.20.1", "mods"),
		join(mc, "versions", "1.20.1-forge-47.2.0", "mods"),
	}
	for _, d := range okDirs {
		if _, ok := resolveManagedModsDir(mc, d); !ok {
			t.Errorf("expected managed dir: %s", d)
		}
	}

	badDirs := []string{
		mc,                                  // mcDir 根
		join(mc, "libraries"),              // 非 mods
		join(mc, "libraries", "com"),       // 任意库目录
		join(mc, "saves"),
		join(mc, "versions"),               // versions 根
		join(mc, "versions", "1.20.1"),     // 版本目录本身
		join(mc, "mods", "sub"),            // mods 子目录
		join(mc, "versions", "1.20", "mods", "sub"),
		join(mc, "mods", "..", "libraries"),
		filepath.Join(filepath.Dir(mc), "outside"),
		"",
	}
	for _, d := range badDirs {
		if _, ok := resolveManagedModsDir(mc, d); ok {
			t.Errorf("expected NOT managed dir: %q", d)
		}
	}
}

func TestSameManagedModDirCrossPlatform(t *testing.T) {
	base := t.TempDir()
	g := filepath.Join(base, "mods", "a.jar.disabled")
	gTo := filepath.Join(base, "mods", "a.jar")
	if !sameManagedModDir(g, gTo) {
		t.Error("same dir enable toggle should be true")
	}
	v := filepath.Join(base, "versions", "v1", "mods", "a.jar.disabled")
	if sameManagedModDir(v, gTo) {
		t.Error("cross-dir toggle should be false")
	}
}
