package main

// motdguard.go —— 服务器描述 / MOTD / 游戏日志“展示安全”统一净化内核。
//
// 威胁模型：
//   Minecraft 服务器可以通过 MOTD、聊天、计分板等把攻击者可控文本送进
//   启动器的控制台 / 日志 UI / 崩溃上下文。这类文本里除了普通控制字符，还常见：
//     - 终端转义序列：CSI（ESC[ … 终止字节）改色 / 清屏 / 光标移动、OSC
//       （ESC] … BEL/ST）改窗口标题，甚至 ESC c 复位终端——单剥 ESC 会残留
//       “[31m” 这类可见垃圾，注入的核心其实是“整段序列”；
//     - Minecraft 格式码：§ + [0-9a-fk-or] 十六种颜色 / 格式码，直接显示会
//       变成 “§a” 乱码，语义上又是“代码”，需要结构化解析而不是照抄；
//     - 双向 / 隐形字符：U+202E 右到左覆盖、零宽空格等可把日志行重新排版，
//       用于仿冒文件名或用户名（“txt.exe” 伪装）。
//   写入侧（validateServerMotd 等）已拒 ASCII 控制字符；本内核管“读取/展示侧”：
//   无论文本来自日志、服务器查询还是外部编辑过的 server.properties，进入
//   UI 前先过这里，保证任何序列都失效、格式码可渲染、长度有界。
//
//   设计：全部是纯函数、不碰 IO、不依赖正则（显式 rune/字节判定），便于穷举测试。
//   ServerTextForDisplay 是“一行安全文本”的快捷方式；MOTDSegmentsToHTML 输出
//   白名单 span（内容一律转义），绝不放行任意 HTML。

import (
	"strings"
)

// motdMaxDisplayLen 是单条服务器文本进入 UI 的最大字节数。
const motdMaxDisplayLen = 300

// motdTruncateMarker 追加在被截断的展示文本末尾。
const motdTruncateMarker = " …[已截断]"

// MOTDColor 是 Minecraft 格式码 §x 的十六种基础颜色名（含 format 型）。
type MOTDSegment struct {
	Text          string // 本段纯文本（不含 § 码）
	Color         byte   // '0'-'f' 颜色码；无颜色时为 0
	Bold          bool
	Italic        bool
	Underline     bool
	Strikethrough bool
	Obfuscated    bool
}

// motdFormat 记录一个 § 格式码的解析结果。
type motdFormat struct {
	color                                              byte
	bold, italic, underline, strikethrough, obfuscated bool
}

// parseMOTDFormat 把 § 后的单个格式码映射为格式。§r 重置全部格式。
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
