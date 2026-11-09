package main

import (
	"strings"
)

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
