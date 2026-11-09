package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsValidMavenToken(t *testing.T) {
	good := []string{
		"a", "org", "lwjgl", "3.3.1", "1.20.1-47.2.0",
		"natives-windows", "21.0.0-beta", "1.17+build.61", "x_y-1.2",
	}
	for _, token := range good {
		if !isValidMavenToken(token) {
			t.Errorf("合法 Maven token 被误拒: %q", token)
		}
	}

	bad := []string{
		"", ".", "..", "../x", "a/../b", "a\\b",
		"a b", "a\tb", "a\nb", "C:", "C:\\windows",
		"a|b", "a*b", "a?b", "a<b>", "a:b",
	}
	for _, token := range bad {
		// 反斜杠只有在 Windows 上是分隔符；类 Unix 系统下它只是普通文件名字符，
		// 那种输入由后面的 isSafeRelPath 兜底用例覆盖。
		if strings.ContainsAny(token, `\`) && runtime.GOOS != "windows" {
			continue
		}
		if isValidMavenToken(token) {
			t.Errorf("非法 Maven token 未被拒绝: %q", token)
		}
	}

	long := strings.Repeat("a", 256)
	if isValidMavenToken(long) {
		t.Error("长度超过 255 的 token 必须被拒绝")
	}
}

func TestMavenNameToPathHappy(t *testing.T) {
	libs := filepath.Clean(t.TempDir())
	cases := []struct {
		name   string
		coords string
		suffix string
	}{
		{"无 classifier", "org.lwjgl:lwjgl:3.3.1",
			filepath.Join("org", "lwjgl", "lwjgl", "3.3.1", "lwjgl-3.3.1.jar")},
		{"带 classifier", "org.lwjgl:lwjgl:3.3.1:natives-windows",
			filepath.Join("org", "lwjgl", "lwjgl", "3.3.1", "lwjgl-3.3.1-natives-windows.jar")},
		{"Forge 坐标", "net.minecraftforge:forge:1.20.1-47.2.0",
			filepath.Join("net", "minecraftforge", "forge", "1.20.1-47.2.0", "forge-1.20.1-47.2.0.jar")},
		{"多层 groupId", "com.mojang.realms:realms:1.0",
			filepath.Join("com", "mojang", "realms", "realms", "1.0", "realms-1.0.jar")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mavenNameToPath(tc.coords, libs)
			want := filepath.Join(libs, tc.suffix)
			if got != want {
				t.Fatalf("坐标 %q 路径不符:\n got=%q\nwant=%q", tc.coords, got, want)
			}
			// 无论怎么拼，结果都必须留在 libraries 目录内。
			rel, err := filepath.Rel(libs, got)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("坐标 %q 拼出了 libraries 之外的路径: %q", tc.coords, got)
			}
		})
	}
}

func TestMavenNameToPathRejectsTraversal(t *testing.T) {
	libs := filepath.Clean(t.TempDir())
	malicious := []string{
		"org.lwjgl:lwjgl",                 // 段数不足
		"org.lwjgl:lwjgl:",                // 空版本
		"..:lwjgl:3.3.1",                  // groupId 是 ..
		"org..evil:lwjgl:3.3.1",           // groupId 含 .. 段
		"org/../../evil:lwjgl:3.3.1",      // groupId 带正斜杠穿越
		"org.lwjgl:../lwjgl:3.3.1",        // artifact 穿越
		"org.lwjgl:lwjgl:../../x",         // classifier 穿越
		"org.lwjgl:lwjgl:3.3.1:x y",       // classifier 含空格
		"org.lwjgl:lwjgl:3.3.1:a|b",       // classifier 含管道符
		"evil group:lwjgl:3.3.1",          // groupId 含空格
		strings.Repeat("a", 300) + ":b:1", // 超长 groupId
	}
	for _, coords := range malicious {
		if got := mavenNameToPath(coords, libs); got != "" {
			t.Errorf("恶意坐标 %q 应返回空路径，实际得到 %q", coords, got)
		}
	}

	// 反斜杠穿越是 Windows 特有的分隔符语义，单独在 Windows 上验证。
	if runtime.GOOS == "windows" {
		for _, coords := range []string{
			"a\\..\\b:art:1",
			"org.lwjgl:lwjgl:..\\x",
		} {
			if got := mavenNameToPath(coords, libs); got != "" {
				t.Errorf("Windows 恶意坐标 %q 应返回空路径，实际得到 %q", coords, got)
			}
		}
	}
}

func TestIsSafeRelPathRejectsEscape(t *testing.T) {
	unsafe := []string{
		"", "..", "../x", "a/../../b", "a/b/../../../etc/passwd",
		"/etc/passwd", "a//../../b",
	}
	for _, p := range unsafe {
		if got := isSafeRelPath(p); got != "" {
			t.Errorf("逃逸路径 %q 必须被拒绝，实际返回 %q", p, got)
		}
	}
	safe := []string{
		"a.jar", "org/lwjgl/lwjgl.jar", "a/b/c/d.dll",
		"./x/y.jar", "a/./b.jar",
	}
	for _, p := range safe {
		if got := isSafeRelPath(p); got == "" {
			t.Errorf("正常相对路径 %q 不应被拒绝", p)
		}
	}
}
