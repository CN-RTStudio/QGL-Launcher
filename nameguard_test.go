package main

import (
	"testing"
)

func TestAuditComponentAccepts(t *testing.T) {
	// 合法：中文名、空格、括号、内部点号、loader 风格版本号都应放行。
	accepted := []string{
		"1.20.1",
		"fabric-loader-0.16.10",
		"我的整合包 v2",
		"Forge Pack (forge 47.2.0)",
		"a b c",
		"weird..but..ok",
		"name-with_under+sign",
		"mods 2.0 (beta)",
	}
	for _, in := range accepted {
		if why := auditComponent(in, maxVersionDisplayLen); why != nameRejectNone {
			t.Errorf("auditComponent(%q) 被误拒: %s", in, why)
		}
	}
}

func TestAuditComponentRejects(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"", nameRejectEmpty},
		{"   ", nameRejectEmpty},
		{"\t\n", nameRejectEmpty},
		{"a\x00b", nameRejectControl},
		{"evil\nname", nameRejectControl},
		{"cr\rlf", nameRejectControl},
		{"esc\x1b[31m", nameRejectControl},
		{"a/b", nameRejectSeparator},
		{"a\\b", nameRejectSeparator},
		{"../x", nameRejectSeparator},
		{"a:b", nameRejectForbidden},
		{"star*", nameRejectForbidden},
		{"q?", nameRejectForbidden},
		{"\"q\"", nameRejectForbidden},
		{"a<b>", nameRejectForbidden},
		{"pipe|", nameRejectForbidden},
		{".", nameRejectTraversal},
		{"..", nameRejectTraversal},
		{" leadspace", nameRejectOuterSpace},
		{"trailspace ", nameRejectOuterSpace},
		{".hidden", nameRejectOuterDot},
		{"traildot.", nameRejectOuterDot},
		{"CON", nameRejectReserved},
		{"con", nameRejectReserved},
		{"Con.txt", nameRejectReserved},
		{"nul.", nameRejectReserved},
		{"COM1 ", nameRejectReserved},
		{"lpt9.jar", nameRejectReserved},
		{"PRN.anything.here", nameRejectReserved},
	}
	for _, tc := range cases {
		if got := auditComponent(tc.name, maxVersionDisplayLen); got != tc.want {
			t.Errorf("auditComponent(%q) = %q, 期望 %q", tc.name, got, tc.want)
		}
	}
}

func TestAuditComponentLength(t *testing.T) {
	short := make([]byte, maxVersionComponentLen)
	for i := range short {
		short[i] = 'a'
	}
	if why := auditComponent(string(short), maxVersionComponentLen); why != nameRejectNone {
		t.Errorf("恰好达到上限的名字应放行, got %s", why)
	}
	long := make([]byte, maxVersionComponentLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if why := auditComponent(string(long), maxVersionComponentLen); why != nameRejectLength {
		t.Errorf("超长名字应被拒, got %s", why)
	}
}

func TestIsReservedDeviceName(t *testing.T) {
	yes := []string{"CON", "con", "Prn", "NUL", "aux", "COM1", "com9", "LPT1", "lpt9"}
	for _, s := range yes {
		if !isReservedDeviceName(s) {
			t.Errorf("%q 应判为保留设备名", s)
		}
	}
	no := []string{"COM0", "COM10", "LPT", "CONSOLE", "CONE", "NULLED", ""}
	for _, s := range no {
		if isReservedDeviceName(s) {
			t.Errorf("%q 不应判为保留设备名", s)
		}
	}
}

func TestSafeVersionComponent(t *testing.T) {
	// 首尾空白被确定性去掉，内部保留。
	clean, why := SafeVersionComponent("  1.20.1-fabric  ")
	if why != nameRejectNone || clean != "1.20.1-fabric" {
		t.Fatalf("归一化结果异常: %q %q", clean, why)
	}
	// 穿越/控制字符必须直接拒绝而不是静默删除。
	if _, why := SafeVersionComponent("../../etc/passwd"); why != nameRejectSeparator {
		t.Fatalf("穿越名应被拒, got %q", why)
	}
	if _, why := SafeVersionComponent("a\x00b"); why != nameRejectControl {
		t.Fatalf("NUL 应被拒, got %q", why)
	}
}

func TestSafeLoaderComponent(t *testing.T) {
	good := []string{"fabric", "0.16.10", "47.2.0", "21.1.74", "1.0.0-beta"}
	for _, in := range good {
		if _, why := SafeLoaderComponent(in); why != nameRejectNone {
			t.Errorf("loader 组件 %q 被误拒: %s", in, why)
		}
	}
	bad := []string{"", "  ", "0.16/10", "a\nb", "CON", "trailingdot.", "x y"}
	// 注意 loader 组件里空格不合法（会被拼进展示名，已由外层展示名承载空格）。
	for _, in := range bad {
		if _, why := SafeLoaderComponent(in); why == nameRejectNone {
			t.Errorf("loader 组件 %q 应被拒", in)
		}
	}
	long := ""
	for i := 0; i < maxLoaderComponentLen+1; i++ {
		long += "a"
	}
	if _, why := SafeLoaderComponent(long); why != nameRejectLength {
		t.Fatalf("超长 loader 版本应被拒, got %q", why)
	}
}
