package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

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

func TestSafeExts(t *testing.T) {
	if !IsSafeImageExt("a.PNG") || !IsSafeArchiveExt("p.MRPACK") {
		t.Error("扩展名匹配应大小写不敏感")
	}
	if IsSafeImageExt("a.exe") || IsSafeArchiveExt("a.jar") {
		t.Error("非白名单扩展名必须拒绝")
	}
}

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
