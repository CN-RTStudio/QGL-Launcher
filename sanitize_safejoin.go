package main

import (
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func SafeJoin(root string, rel string) (string, bool) {
	if root == "" || rel == "" {
		return "", false
	}
	// 绝对路径 / 盘符 / UNC：filepath.Join 会把它们当成“已绝对”直接吞掉 root。
	// Windows 下 "/abs/x" 不算 IsAbs（只是“当前盘根”），但它表达的是绝对意图，
	// 静默改成 root\abs\x 会让调用方写错位置，这里一并拒绝。
	if filepath.IsAbs(rel) || filepath.VolumeName(rel) != "" ||
		strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, `\`) {
		return "", false
	}
	// 旧实现先拼成 "/"+rel 再 Clean，在 Windows 上 Clean("/") 返回反斜杠根，
	// TrimPrefix 剥不掉，导致 ""/"."/".." 被拼成 root 本身并放行；同时 "../x"
	// 被归一化成 "x" 静默落到 root 内另一个文件，调用方以为写的是别处。
	// 这里改成逐段白名单式拼接：任何 ".." 段直接拒绝，不做“归一化吞掉”。
	segs := strings.Split(strings.ReplaceAll(rel, `\`, "/"), "/")
	parts := make([]string, 0, len(segs)+1)
	parts = append(parts, root)
	for _, seg := range segs {
		if seg == "" || seg == "." {
			continue
		}
		if seg == ".." {
			return "", false
		}
		parts = append(parts, seg)
	}
	if len(parts) == 1 {
		return "", false
	}
	full := filepath.Join(parts...)
	if _, ok := PathWithin(root, full); !ok {
		return "", false
	}
	return full, true
}

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
