package main

import (
	"strings"
	"unicode/utf8"
)

func SanitizeFilename(name string) string {
	if name == "" {
		return name
	}
	// Windows 保留字符
	for _, c := range []string{`<`, `>`, `:`, `"`, `/`, `\`, `|`, `?`, `*`} {
		name = strings.ReplaceAll(name, c, "_")
	}
	// 不可见空白（U+00A0 不换行空格、U+2000–U+200A 各种窄空格、U+202F、
	// U+205F、U+3000 表意空格、U+1680 欧甘空格）在资源管理器里和普通空格几乎
	// 无法区分，下面的 TrimLeft/TrimRight(" .") 又不会处理它们：名字尾部留一个
	// U+00A0 时磁盘上实际是 `x .jar`，审计日志里看到的却是 `x .jar`，可用来做
	// 扩展名视觉混淆。统一换成下划线，保证审计名与实际落盘名逐字节一致。
	name = strings.Map(func(r rune) rune {
		if r == '\u00A0' || r == '\u1680' || r == '\u202F' || r == '\u205F' || r == '\u3000' || (r >= '\u2000' && r <= '\u200A') {
			return '_'
		}
		return r
	}, name)
	// 去掉首尾空格和点（Windows 不允许文件名以点结尾）
	name = strings.TrimLeft(name, " .")
	name = strings.TrimRight(name, " .")
	name = truncateFilenameBytes(name, 128)
	// 截断可能重新落在点/空格上，再剥一次，保证审计名与磁盘名一致。
	name = strings.TrimRight(name, " .")
	if name == "" {
		return name
	}
	// Windows 保留设备名（CON / PRN / AUX / NUL / COM1..9 / LPT1..9）带扩展名也会
	// 落到设备上（CON.txt 仍写进控制台），加下划线前缀让它变成普通文件。
	// 原实现只替换非法字符，保留名会原样放行，写入会失败或丢数据。
	if isReservedDeviceName(stemOfName(name)) {
		name = "_" + name
	}
	return name
}

// truncateFilenameBytes 把文件名截到 max 字节，并回退到合法 UTF-8 边界。
// 直接切字节会把多字节字符劈成半个，Windows 落盘会直接拒绝该名字。
func truncateFilenameBytes(name string, max int) string {
	if max <= 0 || len(name) <= max {
		return name
	}
	cut := name[:max]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// ValidateModName 校验 mod / 版本 ID 是否合法：
// 只允许字母数字、点、下划线、短横线，长度 1~64。
// 这是 Minecraft 版本目录、mod 文件名的实际约定。
func ValidateModName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
