package main

import "strings"

// MOTDSegmentsToPlain 把分段重新拼成纯文本（无 § 码、无样式标记）。
func MOTDSegmentsToPlain(segs []MOTDSegment) string {
	var b strings.Builder
	for _, seg := range segs {
		b.WriteString(seg.Text)
	}
	return b.String()
}

// escapeHTMLText 转义 HTML 特殊字符，保证任何文本都不能借渲染逃逸成标签。
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

// motdHexToCSS 把 Minecraft 16 色码映射为展示色。§r 等无色段返回空串。
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

// MOTDSegmentsToHTML 把分段渲染成白名单 HTML：每个段包在 span 里，样式只
// 来自颜色/格式码映射；文本一律经 escapeHTMLText。任何情况下不放行标签。
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

// joinStyle 用分号连接两段样式（跳过空段），供 span 样式组装。
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
