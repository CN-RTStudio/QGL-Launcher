package main

import (
	"testing"
)

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
		"":                 nameRejectEmpty,
		"   ":              nameRejectEmpty,
		"evil.sh":          nameRejectExtension,
		"mod.exe":          nameRejectExtension,
		"mod.jar.exe":      nameRejectExtension,
		"a\x00b.jar":       nameRejectControl,
		"CON.jar":          nameRejectReserved,
		"nul.jar.disabled": nameRejectReserved,
		"mod.jar/..":       nameRejectTraversal, // Base 剥离后剩 ".."
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
		0x00AD,         // 软连字符
		0x180E,         // 蒙古文元音分隔符
		0x2028, 0x2029, // 行 / 段分隔符
		0x2060, 0x2061, 0x2064, // 字连接符 / 不可见运算符
		0x206A, 0x206B, 0x206F, // 废弃格式符
		0xFEFF, // BOM / 零宽不换行空格
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
		"":            nameRejectEmpty,
		"..":          nameRejectTraversal,
		"a/b":         nameRejectSeparator,
		"CON":         nameRejectReserved,
		"nul.txt":     nameRejectReserved,
		"COM1":        nameRejectReserved,
		"a:b":         nameRejectForbidden, // NTFS 备用数据流
		"steve\u200b": nameRejectInvisible,
		"exe\u202ex":  nameRejectBidi,
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
