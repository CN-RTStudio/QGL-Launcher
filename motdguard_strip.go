package main

import (
	"strings"
)

func stripMCFormatCodes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r != 0x00a7 { // '§'
			b.WriteRune(r)
			continue
		}
		// § 后紧跟合法格式码：整组剥掉；否则只剥孤立 §。
		if i+1 < len(runes) && isMOTDFormatCode(runes[i+1]) {
			i++
		}
	}
	return b.String()
}

// stripBidiAndInvisibles 剥除双向控制与零宽字符，防“重新排版仿冒”。
// 覆盖 U+200B 零宽空格、U+200E/U+200F 左右嵌入、U+202A-U+202E 双向覆盖、
// U+2060 词连接、U+2066-U+2069 隔离、U+FEFF BOM/零宽不换行。
func stripBidiAndInvisibles(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == 0x200b || r == 0x200e || r == 0x200f:
			continue
		case r >= 0x202a && r <= 0x202e:
			continue
		case r == 0x2060 || r == 0x2066 || r == 0x2067 || r == 0x2068 || r == 0x2069:
			continue
		case r == 0xfeff:
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// stripDisplayControlChars 剥掉剩余的 ASCII 控制字符（保留制表符），
// 与 stripLogControlChars 语义一致，供展示链路统一调用。
func stripDisplayControlChars(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
