package main

import ()

const motdMaxDisplayLen = 300
const motdTruncateMarker = " …[已截断]"

type MOTDSegment struct {
	Text          string // 本段纯文本（不含 § 码）
	Color         byte   // '0'-'f' 颜色码；无颜色时为 0
	Bold          bool
	Italic        bool
	Underline     bool
	Strikethrough bool
	Obfuscated    bool
}
type motdFormat struct {
	color                                              byte
	bold, italic, underline, strikethrough, obfuscated bool
}

func parseMOTDFormat(code rune) motdFormat {
	// '0'-'9' 与 'a'-'f'：颜色（Minecraft 传统 16 色）。
	if (code >= '0' && code <= '9') || (code >= 'a' && code <= 'f') {
		return motdFormat{color: byte(code)}
	}
	// 'k'-'o'：格式（混淆/粗体/斜体/下划线/删除线）；'r' 重置。
	switch code {
	case 'k':
		return motdFormat{obfuscated: true}
	case 'l':
		return motdFormat{bold: true}
	case 'm':
		return motdFormat{strikethrough: true}
	case 'n':
		return motdFormat{underline: true}
	case 'o':
		return motdFormat{italic: true}
	case 'r':
		return motdFormat{} // 重置：全 false
	}
	return motdFormat{}
}

// isMOTDFormatCode 判断 rune 是否是可跟 § 的格式码。
