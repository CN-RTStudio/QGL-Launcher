package main

import "testing"

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

func TestSafeVersionDisplayName(t *testing.T) {
	ok := "我的包 (forge 47.2.0)"
	if clean, why := SafeVersionDisplayName(ok); why != nameRejectNone || clean != ok {
		t.Fatalf("正常展示名应放行: %q %q", clean, why)
	}
	// customName 本身合法，但拼上 loader 后超长也必须拒，避免截断后落盘到意外目录。
	longCustom := ""
	for i := 0; i < maxVersionComponentLen; i++ {
		longCustom += "a"
	}
	combined := longCustom + " (fabric 0.16.10)"
	if _, why := SafeVersionDisplayName(combined); why != nameRejectLength {
		t.Fatalf("拼接后超长应被拒, got %q", why)
	}
}

func TestSafeModFileName(t *testing.T) {
	ok := []string{
		"sodium-fabric-0.5.8.jar",
		"JEI 1.20.1.jar",
		"legacy-coremod.zip",
		"disabled-mod.jar.disabled",
	}
	for _, in := range ok {
		if got, why := SafeModFileName(in); why != nameRejectNone {
			t.Errorf("模组名 %q 被误拒: %s (%q)", in, why, got)
		}
	}
	// 即使塞了目录，也只取最后一段，最后一段合法即放行。
	if got, why := SafeModFileName("dir/sub/mod.jar"); why != nameRejectNone || got != "mod.jar" {
		t.Fatalf("带目录的模组名应剥离目录, got %q %q", got, why)
	}
	bad := map[string]string{
		"":                      nameRejectEmpty,
		"   ":                   nameRejectEmpty,
		"evil.sh":               nameRejectExtension,
		"mod.exe":               nameRejectExtension,
		"mod.jar.exe":           nameRejectExtension,
		"a\x00b.jar":            nameRejectControl,
		"CON.jar":               nameRejectReserved,
		"nul.jar.disabled":      nameRejectReserved,
		"mod.jar/..":            nameRejectTraversal, // Base 剥离后剩 ".."
	}
	for in, want := range bad {
		_, why := SafeModFileName(in)
		if why != want {
			t.Errorf("SafeModFileName(%q) = %q, 期望 %q", in, why, want)
		}
	}
	// 目录段会被 Base 剥离，最后一段合法即放行（穿越在剥离后已失效）。
	if got, why := SafeModFileName("../escape.jar"); why != nameRejectNone || got != "escape.jar" {
		t.Errorf("带 ../ 的模组名应剥离目录后放行, got %q %q", got, why)
	}
	// 内部空格合法。
	if _, why := SafeModFileName("trailing .jar"); why != nameRejectNone {
		t.Errorf("内部空格的模组名应放行, got %q", why)
	}
}

func TestDescribeNameReject(t *testing.T) {
	if describeNameReject(nameRejectNone) == "" {
		t.Fatal("通过态也应给出说明文字")
	}
	for _, code := range []string{
		nameRejectEmpty, nameRejectControl, nameRejectSeparator, nameRejectForbidden,
		nameRejectTraversal, nameRejectReserved, nameRejectOuterSpace, nameRejectOuterDot,
		nameRejectLength, nameRejectExtension, nameRejectInvisible, nameRejectBidi,
		nameRejectNonchar,
	} {
		if describeNameReject(code) == "" {
			t.Errorf("原因码 %s 缺少中文说明", code)
		}
	}
	if got := describeNameReject("unknown-code"); got == "" {
		t.Fatal("未知原因码也应有兜底说明")
	}
}

func TestUnsafeRuneCode(t *testing.T) {
	invisible := []rune{
		0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // 零宽空格 / 连接符 / 左右方向标记
		0x00AD,                   // 软连字符
		0x180E,                   // 蒙古文元音分隔符
		0x2028, 0x2029,           // 行 / 段分隔符
		0x2060, 0x2061, 0x2064,   // 字连接符 / 不可见运算符
		0x206A, 0x206B, 0x206F,   // 废弃格式符
		0xFEFF,                   // BOM / 零宽不换行空格
	}
	for _, r := range invisible {
		if got := unsafeRuneCode(r); got != nameRejectInvisible {
			t.Errorf("U+%04X 应判为不可见字符, got %q", r, got)
		}
	}
	bidi := []rune{0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
	for _, r := range bidi {
		if got := unsafeRuneCode(r); got != nameRejectBidi {
			t.Errorf("U+%04X 应判为双向覆写字符, got %q", r, got)
		}
	}
	nonchar := []rune{0xFFFE, 0xFFFF, 0xFDD0, 0xFDEF, 0xFDD1, 0xFDE0, 0x10FFFF, 0x10FFFE}
	for _, r := range nonchar {
		if got := unsafeRuneCode(r); got != nameRejectNonchar {
			t.Errorf("U+%04X 应判为非字符, got %q", r, got)
		}
	}
	// 正常可见字符（含中文、空格、普通 emoji、NBSP）一律放行，零误伤。
	safe := []rune{'a', '0', '.', ' ', '_', '中', 0x00A0, 0x1F600, 0x4E2D}
	for _, r := range safe {
		if got := unsafeRuneCode(r); got != nameRejectNone {
			t.Errorf("U+%04X 不应被拦, got %q", r, got)
		}
	}
}

func TestAuditComponentUnicode(t *testing.T) {
	// 同形异义 / 仿冒攻击用名字必须被拒（全部用 \u 转义，避免源码里藏不可见字符）。
	reject := map[string]string{
		"steve\u200bname": nameRejectInvisible, // 夹带 U+200B 零宽空格
		"steve\u00adname": nameRejectInvisible, // 夹带 U+00AD 软连字符
		"exe\u202eevil":   nameRejectBidi,      // 夹带 U+202E 右向左覆写
		"a\u2066b\u2069":  nameRejectBidi,      // U+2066 / U+2069 隔离
		"name\ufeff":      nameRejectInvisible, // 结尾 U+FEFF
		"name\uffff":      nameRejectNonchar,   // U+FFFF
		"name\ufdd0":      nameRejectNonchar,   // U+FDD0
	}
	for in, want := range reject {
		if got := auditComponent(in, maxVersionDisplayLen); got != want {
			t.Errorf("auditComponent(%q) = %q, 期望 %q", in, got, want)
		}
	}
	// 合法多字节 / emoji 名字继续放行。
	accepted := []string{"史蒂夫", "玩家_2024", "mod 模组 😀", "Alex マイクラ"}
	for _, in := range accepted {
		if why := auditComponent(in, maxVersionDisplayLen); why != nameRejectNone {
			t.Errorf("合法名字 %q 被误拒: %s", in, why)
		}
	}
}

func TestSafeAccountName(t *testing.T) {
	good := []string{"Steve_2024", "  史蒂夫  ", "player-01"}
	for _, in := range good {
		if clean, why := SafeAccountName(in); why != nameRejectNone {
			t.Errorf("账户名 %q 被误拒: %s", in, why)
		} else if clean == "" {
			t.Errorf("账户名归一化异常")
		}
	}
	// 历史 validateUsername 漏掉、现在必须堵住的账户目录段攻击。
	bad := map[string]string{
		"":              nameRejectEmpty,
		"..":            nameRejectTraversal,
		"a/b":           nameRejectSeparator,
		"CON":           nameRejectReserved,
		"nul.txt":       nameRejectReserved,
		"COM1":          nameRejectReserved,
		"a:b":           nameRejectForbidden, // NTFS 备用数据流
		"steve\u200b":   nameRejectInvisible,
		"exe\u202ex":    nameRejectBidi,
	}
	for in, want := range bad {
		if _, why := SafeAccountName(in); why != want {
			t.Errorf("SafeAccountName(%q) = %q, 期望 %q", in, why, want)
		}
	}
	// 长度上限沿用历史 64。
	long := ""
	for i := 0; i < maxAccountNameLen+1; i++ {
		long += "a"
	}
	if _, why := SafeAccountName(long); why != nameRejectLength {
		t.Fatalf("超长账户名应被拒, got %q", why)
	}
}

func TestIsSafeFileNameReserved(t *testing.T) {
	// 加载器版本号是严格 ASCII 白名单，但纯字母数字保留设备名仍需被挡。
	bad := []string{"CON", "nul", "COM1", "lpt9", "PRN.txt", "AUX.jar"}
	for _, in := range bad {
		if isSafeFileName(in) {
			t.Errorf("isSafeFileName(%q) 应拒绝保留设备名", in)
		}
	}
	good := []string{"53.0.12", "0.16.10", "47.2.0", "forge-1.20.1", "HD_U_Pre"}
	for _, in := range good {
		if !isSafeFileName(in) {
			t.Errorf("isSafeFileName(%q) 应放行正常加载器版本号", in)
		}
	}
}

