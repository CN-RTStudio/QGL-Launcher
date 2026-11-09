package main

import (
	"strings"
	"testing"
)

// feedByChunks 用指定块大小把 data 喂给新建的切分器，最后 Flush，收集全部行。
func feedByChunks(t *testing.T, maxLine int, data string, chunk int) []string {
	t.Helper()
	s := newBoundedLineSplitter(maxLine)
	var got []string
	src := []byte(data)
	for off := 0; off < len(src); off += chunk {
		end := off + chunk
		if end > len(src) {
			end = len(src)
		}
		got = append(got, s.Feed(src[off:end])...)
	}
	got = append(got, s.Flush()...)
	return got
}

// expectChunkSizes 是一组会把行从任意位置切开的块大小，用于验证状态机与分块无关。
var expectChunkSizes = []int{1, 2, 3, 5, 7, 64, 4096}

func TestBoundedSplitterBasicLinesAllChunkings(t *testing.T) {
	in := "alpha\nbeta\ngamma\n"
	want := []string{"alpha", "beta", "gamma"}
	for _, ch := range expectChunkSizes {
		got := feedByChunks(t, 1024, in, ch)
		if len(got) != len(want) {
			t.Fatalf("chunk=%d got %d lines %q, want %d", ch, len(got), got, len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("chunk=%d line %d = %q want %q", ch, i, got[i], want[i])
			}
		}
	}
}

func TestBoundedSplitterCRLFStripped(t *testing.T) {
	in := "a\r\nb\r\nc"
	want := []string{"a", "b", "c"}
	for _, ch := range expectChunkSizes {
		got := feedByChunks(t, 1024, in, ch)
		if len(got) != len(want) {
			t.Fatalf("chunk=%d CRLF 切分行数错误: %q", ch, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("chunk=%d line %d = %q want %q", ch, i, got[i], want[i])
			}
		}
	}
}

func TestBoundedSplitterEmptyLines(t *testing.T) {
	in := "\n\nx\n\n"
	want := []string{"", "", "x", ""}
	for _, ch := range expectChunkSizes {
		got := feedByChunks(t, 1024, in, ch)
		if len(got) != len(want) {
			t.Fatalf("chunk=%d 空行数量错误 got=%q want=%q", ch, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("chunk=%d line %d = %q want %q", ch, i, got[i], want[i])
			}
		}
	}
}

func TestBoundedSplitterNoTrailingNewline(t *testing.T) {
	in := "only"
	for _, ch := range expectChunkSizes {
		got := feedByChunks(t, 1024, in, ch)
		if len(got) != 1 || got[0] != "only" {
			t.Fatalf("chunk=%d 无结尾换行处理错误: %q", ch, got)
		}
	}
}

func TestBoundedSplitterEmptyInput(t *testing.T) {
	for _, ch := range []int{1, 64} {
		got := feedByChunks(t, 1024, "", ch)
		if len(got) != 0 {
			t.Fatalf("空输入不应产生行, got=%q", got)
		}
	}
}

func TestBoundedSplitterExactlyAtLimit(t *testing.T) {
	// 行长度恰好等于上限（按字节），且正常换行结束：必须原样返回，不算截断。
	maxLine := 16
	body := strings.Repeat("A", maxLine)
	in := body + "\nnext\n"
	for _, ch := range expectChunkSizes {
		got := feedByChunks(t, maxLine, in, ch)
		if len(got) != 2 {
			t.Fatalf("chunk=%d 行数错误 %q", ch, got)
		}
		if got[0] != body {
			t.Fatalf("chunk=%d 恰好上限应原样返回，len=%d", ch, len(got[0]))
		}
		if got[1] != "next" {
			t.Fatalf("chunk=%d 第二行错误 %q", ch, got[1])
		}
	}
}

func TestBoundedSplitterTruncateLongLineWithNewline(t *testing.T) {
	maxLine := 16
	in := strings.Repeat("X", 40) + "\nshort\n"
	for _, ch := range expectChunkSizes {
		s := newBoundedLineSplitter(maxLine)
		var got []string
		src := []byte(in)
		for off := 0; off < len(src); off += ch {
			end := off + ch
			if end > len(src) {
				end = len(src)
			}
			got = append(got, s.Feed(src[off:end])...)
		}
		got = append(got, s.Flush()...)
		if len(got) != 2 {
			t.Fatalf("chunk=%d 截断后应仍是两行，got=%q (%d)", ch, got, len(got))
		}
		if len(got[0]) > maxLine {
			t.Fatalf("chunk=%d 截断行长度 %d 超过上限 %d", ch, len(got[0]), maxLine)
		}
		if !strings.HasSuffix(got[0], gameLogTruncateMarker) {
			t.Fatalf("chunk=%d 截断行缺少标记: %q", ch, got[0])
		}
		if got[1] != "short" {
			t.Fatalf("chunk=%d 截断行之后的正常行必须继续被解析: %q", ch, got[1])
		}
		if s.TruncatedLines() != 1 || s.Lines() != 2 {
			t.Fatalf("chunk=%d 计数错误 lines=%d truncated=%d",
				ch, s.Lines(), s.TruncatedLines())
		}
	}
}

func TestBoundedSplitterTruncateWithoutNewlineEOF(t *testing.T) {
	// 无换行的巨行，在流结束前就应产出截断前缀（不能等到 EOF 才发现）。
	maxLine := 8
	in := strings.Repeat("Y", 50)
	s := newBoundedLineSplitter(maxLine)
	var early []string
	src := []byte(in)
	ch := 3
	var off int
	for off = 0; off < len(src); off += ch {
		end := off + ch
		if end > len(src) {
			end = len(src)
		}
		early = append(early, s.Feed(src[off:end])...)
		// 一旦产出，必须是有界的截断行。
		for _, l := range early {
			if len(l) > maxLine {
				t.Fatalf("流式阶段就产出了超长行 len=%d", len(l))
			}
		}
	}
	rest := s.Flush()
	if len(early) != 1 {
		t.Fatalf("超长行应在读满上限时立即产出一次，early=%q rest=%q", early, rest)
	}
	if !strings.HasSuffix(early[0], gameLogTruncateMarker) {
		t.Fatalf("缺少截断标记: %q", early[0])
	}
	if len(rest) != 0 {
		t.Fatalf("丢弃态遇到 EOF 不应再产出残余: %q", rest)
	}
	if s.TruncatedLines() != 1 {
		t.Fatalf("truncated=%d want 1", s.TruncatedLines())
	}
}

func TestBoundedSplitterMultipleLongLinesRecover(t *testing.T) {
	// 连续多行超长，每行截断计数都要累加，且短行始终能被解析。
	maxLine := 10
	in := strings.Repeat("A", 30) + "\n" + strings.Repeat("B", 25) + "\nok\n"
	got := feedByChunks(t, maxLine, in, 4)
	if len(got) != 3 {
		t.Fatalf("应得到 3 行 got=%q", got)
	}
	if !strings.HasSuffix(got[0], gameLogTruncateMarker) ||
		!strings.HasSuffix(got[1], gameLogTruncateMarker) {
		t.Fatalf("前两行都应被截断: %q %q", got[0], got[1])
	}
	if got[2] != "ok" {
		t.Fatalf("短行恢复解析错误: %q", got[2])
	}
}

func TestBoundedSplitterCRSplitAcrossChunks(t *testing.T) {
	// CR 与 LF 被切到不同块，也必须正确去掉 CR。
	maxLine := 64
	s := newBoundedLineSplitter(maxLine)
	var got []string
	got = append(got, s.Feed([]byte("abc\r"))...)
	got = append(got, s.Feed([]byte("\ndef\r\n"))...)
	got = append(got, s.Flush()...)
	if len(got) != 2 || got[0] != "abc" || got[1] != "def" {
		t.Fatalf("跨块 CRLF 处理错误: %q", got)
	}
}

func TestStreamBoundedLinesCounts(t *testing.T) {
	in := "one\ntwo\nthree"
	var lines int64
	var collected []string
	n, trunc, err := streamBoundedLines(strings.NewReader(in), 1024, func(l string) {
		collected = append(collected, l)
		lines++
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || trunc != 0 || lines != 3 {
		t.Fatalf("n=%d trunc=%d cb=%d", n, trunc, lines)
	}
	if len(collected) != 3 || collected[2] != "three" {
		t.Fatalf("内容错误 %q", collected)
	}
}

func TestStreamBoundedLinesTruncatedCounter(t *testing.T) {
	in := strings.Repeat("Z", 500) + "\nshort"
	n, trunc, err := streamBoundedLines(strings.NewReader(in), 32, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应计 2 行，实际 %d", n)
	}
	if trunc != 1 {
		t.Fatalf("应有 1 行截断，实际 %d", trunc)
	}
}
