package main

import (
	"strings"
)

// ServerTextForDisplay 把任意服务器可控文本收敛成一行安全展示文本：
// 整段剥终端序列 → 剥 § 格式码 → 剥双向/隐形字符 → 剥残余控制字符 → 限长。
// maxLen <= 0 时使用默认上限。这是“进 UI 前最后一道闸”的默认入口。
func ServerTextForDisplay(s string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = motdMaxDisplayLen
	}
	clean := stripTerminalSequences(s)
	clean = stripMCFormatCodes(clean)
	clean = stripBidiAndInvisibles(clean)
	clean = stripDisplayControlChars(clean)
	if len(clean) <= maxLen {
		return clean
	}
	keep := maxLen - len(motdTruncateMarker)
	if keep < 0 {
		// 预算小到连截断标记都放不下：宁可返回空串，也不违反长度上限。
		return ""
	}
	if keep > len(clean) {
		keep = len(clean)
	}
	return clean[:keep] + motdTruncateMarker
}

// ParseMOTDSegments 把含 § 格式码的 MOTD 解析为分段列表；每段携带当时的
// 颜色/格式快照，供 UI 按白名单渲染。解析后不做长度二次裁剪（调用方可按
// 需要裁剪 Segment.Text）。孤立 §（后不跟合法格式码）视为普通字符保留。
func ParseMOTDSegments(s string, maxLen int) []MOTDSegment {
	if maxLen <= 0 {
		maxLen = motdMaxDisplayLen
	}
	// 先整段剥终端序列（格式码解析只认 §，不许借 ESC 做手脚）。
	s = stripTerminalSequences(s)
	runes := []rune(s)
	var segs []MOTDSegment
	var cur motdFormat
	var buf strings.Builder
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		segs = append(segs, MOTDSegment{
			Text:          buf.String(),
			Color:         cur.color,
			Bold:          cur.bold,
			Italic:        cur.italic,
			Underline:     cur.underline,
			Strikethrough: cur.strikethrough,
			Obfuscated:    cur.obfuscated,
		})
		buf.Reset()
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 0x00a7 {
			// § 后跟合法格式码：切换格式；否则按“孤立 §”剥掉（展示侧不留乱码）。
			if i+1 < len(runes) && isMOTDFormatCode(runes[i+1]) {
				flush()
				cur = parseMOTDFormat(runes[i+1])
				i++
				continue
			}
			continue
		}
		buf.WriteRune(r)
	}
	flush()
	return segs
}
