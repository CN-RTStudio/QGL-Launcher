package main

import (
	"strings"
)

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
