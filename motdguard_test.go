package main

import (
	"strings"
	"testing"
)

// motdguard_test.go —— 展示净化内核的穷举测试：终端序列、§ 格式码、
// 双向/隐形字符、长度有界、分段解析与 HTML 白名单渲染。

func TestStripTerminalSequences(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"csi color", "\x1b[31mred", "red"},
		{"csi with params", "\x1b[38;5;196mgreen", "green"},
		{"csi incomplete param tail", "ab\x1b[31", "ab"}, // 参数阶段耗尽：丢弃到参数末尾
		{"csi terminator only", "a\x1b[m b", "a b"},      // 空参数 CSI
		{"osc title", "t\x1b]0;evil\x07x", "tx"},
		{"osc with st", "t\x1b]8;;evil\x1b\\x", "tx"},
		{"osc unterminated", "\x1b]0;evil", ""},
		{"lone esc", "a\x1bb", "ab"},
		{"esc st pair", "a\x1b\\b", "ab"},
		{"c1 csi", "a\x9b31mb", "ab"}, // 单字节 CSI
		{"plain text", "hello world", "hello world"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripTerminalSequences(tc.in)
			if got != tc.want {
				t.Fatalf("stripTerminalSequences(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripMCFormatCodes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"color codes", "§aGreen §bBlue", "Green Blue"},
		{"format codes", "§lBold§rPlain", "BoldPlain"},
		{"lone section sign", "a§z", "az"},              // z 不是格式码：只剥孤立 §
		{"section followed by non-code", "a§ b", "a b"}, // § 后非格式码：只剥孤立 §
		{"mixed", "§cRed §lBold §nUnder", "Red Bold Under"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripMCFormatCodes(tc.in)
			if got != tc.want {
				t.Fatalf("stripMCFormatCodes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripBidiAndInvisibles(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"rtl override", "a\u202eb\u202cc", "abc"},
		{"zero width space", "a\u200bb", "ab"},
		{"bom zwsp", "a\ufeffb", "ab"},
		{"lre rle", "a\u202ab\u202cc", "abc"},
		{"word joiner", "a\u2060b", "ab"},
		{"isolates", "a\u2066b\u2069c", "abc"},
		{"plain", "hello", "hello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripBidiAndInvisibles(tc.in)
			if got != tc.want {
				t.Fatalf("stripBidiAndInvisibles(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestServerTextForDisplay(t *testing.T) {
	// 组合链路：ESC 注入 + § 码 + 双向字符 + 控制字符全部收敛。
	raw := "\x1b[31m§cR§r§lG\x1b]0;title\x07\x1b[2J\x00plain\x1b"
	got := ServerTextForDisplay(raw, 0)
	if got != "RGplain" {
		t.Fatalf("ServerTextForDisplay(%q) = %q, want %q", raw, got, "RGplain")
	}
	// 无 § 码时正文原样保留，仅剥序列与隐形字符。
	if got := ServerTextForDisplay("hello §a world", 0); got != "hello  world" {
		t.Fatalf("plain with code = %q", got)
	}
	// 限长：超长文本必须截断并带标记，标记本身不超上限。
	long := strings.Repeat("x", motdMaxDisplayLen*2)
	got = ServerTextForDisplay(long, 0)
	if len(got) > motdMaxDisplayLen {
		t.Fatalf("display len %d > max %d", len(got), motdMaxDisplayLen)
	}
	if !strings.HasSuffix(got, motdTruncateMarker) {
		t.Fatalf("truncated text missing marker: %q", got)
	}
	// 自定义上限：预算小于截断标记长度时宁可空串，不违反上限。
	if got := ServerTextForDisplay("abcdef", 3); got != "" {
		t.Fatalf("custom max = %q, want empty", got)
	}
	// 自定义上限：能容纳前缀+标记时正常截断。
	if got := ServerTextForDisplay("abcdef", 20); got != "abcdef" {
		t.Fatalf("no-truncate max = %q", got)
	}
}

func TestParseMOTDSegments(t *testing.T) {
	segs := ParseMOTDSegments("§cRed §lBold", 0)
	if len(segs) != 2 {
		t.Fatalf("segments = %d, want 2", len(segs))
	}
	if segs[0].Text != "Red " || segs[0].Color != 'c' || segs[0].Bold {
		t.Fatalf("seg0 = %+v", segs[0])
	}
	if segs[1].Text != "Bold" || !segs[1].Bold || segs[1].Color != 0 {
		t.Fatalf("seg1 = %+v", segs[1])
	}
	// §r 重置：后续段无色无格式。
	segs = ParseMOTDSegments("§aA§rB", 0)
	if len(segs) != 2 || segs[1].Text != "B" || segs[1].Color != 0 {
		t.Fatalf("reset segs = %+v", segs)
	}
	// ESC 注入混在 § 码里：先剥序列再解析。
	segs = ParseMOTDSegments("\x1b[31m§cC", 0)
	if len(segs) != 1 || segs[0].Text != "C" || segs[0].Color != 'c' {
		t.Fatalf("esc mixed segs = %+v", segs)
	}
	// 孤立 § 视为普通字符（后随非格式码时保留）。
	segs = ParseMOTDSegments("a§z", 0)
	if len(segs) != 1 || segs[0].Text != "az" {
		t.Fatalf("lone section segs = %+v", segs)
	}
}

func TestMOTDSegmentsPlainAndHTML(t *testing.T) {
	segs := ParseMOTDSegments("§cRed §lBold", 0)
	if plain := MOTDSegmentsToPlain(segs); plain != "Red Bold" {
		t.Fatalf("plain = %q", plain)
	}
	html := MOTDSegmentsToHTML(segs)
	if !strings.Contains(html, "color:#ff5555") {
		t.Fatalf("html missing color: %s", html)
	}
	if !strings.Contains(html, "font-weight:bold") {
		t.Fatalf("html missing bold: %s", html)
	}
	if !strings.HasPrefix(html, "<span") {
		t.Fatalf("html not span-wrapped: %s", html)
	}

	// 注入文本必须被转义：<script> 与引号不能逃逸成标签。
	evil := ParseMOTDSegments("<script>alert(1)</script>", 0)
	html = MOTDSegmentsToHTML(evil)
	if strings.Contains(html, "<script>") {
		t.Fatalf("html leaked script tag: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("html not escaped: %s", html)
	}
	quote := ParseMOTDSegments(`"onload="x`, 0)
	html = MOTDSegmentsToHTML(quote)
	if strings.Contains(html, `"onload=`) {
		t.Fatalf("html leaked quoted attribute: %s", html)
	}
}

func TestContainsTerminalInjection(t *testing.T) {
	if !ContainsTerminalInjection("\x1b[31m") {
		t.Fatal("esc csi should be flagged")
	}
	if !ContainsTerminalInjection("a\x1b]0;t\x07") {
		t.Fatal("osc should be flagged")
	}
	if !ContainsTerminalInjection("\x9b") {
		t.Fatal("c1 csi should be flagged")
	}
	if ContainsTerminalInjection("plain §a text") {
		t.Fatal("§ code is not a terminal injection")
	}
	if ContainsTerminalInjection("") {
		t.Fatal("empty is not an injection")
	}
}

func TestMOTDColorMap(t *testing.T) {
	// 全部 16 个传统颜色码都应映射到非空 CSS 色值。
	for code := byte('0'); code <= '9'; code++ {
		if motdHexToCSS(code) == "" {
			t.Fatalf("color %c missing", code)
		}
	}
	for code := byte('a'); code <= 'f'; code++ {
		if motdHexToCSS(code) == "" {
			t.Fatalf("color %c missing", code)
		}
	}
	if motdHexToCSS('r') != "" {
		t.Fatal("reset code should have no color")
	}
}
