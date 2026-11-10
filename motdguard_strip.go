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

func MOTDSegmentsToPlain(segs []MOTDSegment) string {
	var b strings.Builder
	for _, seg := range segs {
		b.WriteString(seg.Text)
	}
	return b.String()
}
func escapeHTMLText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func motdHexToCSS(color byte) string {
	switch color {
	case '0':
		return "#000000"
	case '1':
		return "#0000aa"
	case '2':
		return "#00aa00"
	case '3':
		return "#00aaaa"
	case '4':
		return "#aa0000"
	case '5':
		return "#aa00aa"
	case '6':
		return "#ffaa00"
	case '7':
		return "#aaaaaa"
	case '8':
		return "#555555"
	case '9':
		return "#5555ff"
	case 'a':
		return "#55ff55"
	case 'b':
		return "#55ffff"
	case 'c':
		return "#ff5555"
	case 'd':
		return "#ff55ff"
	case 'e':
		return "#ffff55"
	case 'f':
		return "#ffffff"
	}
	return ""
}

func MOTDSegmentsToHTML(segs []MOTDSegment) string {
	var b strings.Builder
	for _, seg := range segs {
		if seg.Text == "" {
			continue
		}
		style := ""
		if color := motdHexToCSS(seg.Color); color != "" {
			style = "color:" + color
		}
		if seg.Bold {
			style = joinStyle(style, "font-weight:bold")
		}
		if seg.Italic {
			style = joinStyle(style, "font-style:italic")
		}
		if seg.Underline {
			style = joinStyle(style, "text-decoration:underline")
		}
		if seg.Strikethrough {
			style = joinStyle(style, "text-decoration:line-through")
		}
		if seg.Obfuscated {
			style = joinStyle(style, "letter-spacing:2px;opacity:0.85")
		}
		if style == "" {
			b.WriteString(escapeHTMLText(seg.Text))
			continue
		}
		b.WriteString("<span style=\"" + style + "\">")
		b.WriteString(escapeHTMLText(seg.Text))
		b.WriteString("</span>")
	}
	return b.String()
}

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
