package main

import (
	"strings"
)

func joinStyle(a, b string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + ";" + b
}

// ContainsTerminalInjection 检测文本里是否存在活跃终端转义（ESC、OSC 开始、
// BEL 等）。用于审计标记：即使展示侧已剥净，也把“来源可能被污染”记录下来。
func ContainsTerminalInjection(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 0x1b, 0x07, 0x9b: // ESC、BEL、CSI 单字节形态
			return true
		}
	}
	return false
}

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
