package main

import (
	"strings"
)

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
func isMOTDFormatCode(code rune) bool {
	if (code >= '0' && code <= '9') || (code >= 'a' && code <= 'f') {
		return true
	}
	switch code {
	case 'k', 'l', 'm', 'n', 'o', 'r':
		return true
	}
	return false
}

// stripTerminalSequences 整段剥除终端转义序列，而非只删 ESC 单字节：
//
//	CSI：ESC '[' 参数(0x20-0x3f)* 终止(0x40-0x7e)；C1 形态 0x9b 同 CSI
//	OSC：ESC ']' … 直到 BEL(0x07) 或 ST(ESC '\')，或字符串结束
//	其余紧跟 ESC 的形式（ESC c 复位、ESC ( 选择字符集）视作单 ESC 丢弃。
func stripTerminalSequences(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x9b && i+1 < len(s) && s[i+1] >= 0x20 && s[i+1] <= 0x7e {
			// C1 单字节 CSI（0x9b == ESC '['）：同样按 CSI 规则剥除。
			// 只在后随 ASCII（参数 0x20-0x3f / 终止 0x40-0x7e）时触发；
			// 若 0x9b 后随 UTF-8 续字节（0x80-0xbf），它是多字节字符的中继字节，
			// 必须原样保留（例：“相” 的 UTF-8 字节 E7 9B B8 里的 0x9B）。
			j := i + 1
			for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
				j++
			}
			if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
				i = j
				continue
			}
			i = j - 1
			continue
		}
		if c != 0x1b {
			b.WriteByte(c)
			continue
		}
		// 以 ESC 开头：尝试匹配 CSI / OSC / ST，匹配失败至少丢弃该 ESC。
		if i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] >= 0x20 && s[j] <= 0x3f {
				j++
			}
			if j < len(s) && s[j] >= 0x40 && s[j] <= 0x7e {
				i = j // 跳过整个 CSI 序列
				continue
			}
			i = j - 1 // 参数未以终止字节收尾：丢弃到参数末尾
			continue
		}
		if i+1 < len(s) && s[i+1] == ']' {
			j := i + 2
			for j < len(s) {
				if s[j] == 0x07 { // BEL 结束 OSC
					i = j
					break
				}
				if s[j] == 0x1b && j+1 < len(s) && s[j+1] == '\\' { // ST 结束 OSC
					i = j + 1
					break
				}
				j++
			}
			if i < j { // 未找到结束符：丢弃到字符串末尾
				i = len(s) - 1
			}
			continue
		}
		if i+1 < len(s) && s[i+1] == '\\' {
			// 独立 ST（ESC \）：整体丢弃。
			i++
			continue
		}
		// 其它 ESC 开头形式：只丢弃 ESC 本身。
	}
	return b.String()
}

// stripMCFormatCodes 剥掉全部 § 格式码（§ + 合法格式码；孤立 § 也剥掉）。
