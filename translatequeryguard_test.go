package main

import (
	"strings"
	"testing"
)

func TestNormalizeTranslateQuery(t *testing.T) {
	ok := func(in, want string) {
		t.Helper()
		got, good := normalizeTranslateQuery(in)
		if !good {
			t.Fatalf("normalizeTranslateQuery(%q) rejected unexpectedly", in)
		}
		if got != want {
			t.Fatalf("normalizeTranslateQuery(%q) = %q, want %q", in, got, want)
		}
	}
	reject := func(in string) {
		t.Helper()
		if got, good := normalizeTranslateQuery(in); good {
			t.Fatalf("normalizeTranslateQuery(%q) = %q, want rejection", in, got)
		}
	}

	ok("  工业  ", "工业")
	ok("工业\n革命", "工业革命")
	ok("a\tb", "ab")
	ok("nul\x00here", "nulhere")
	ok("del\x7fend", "delend")

	reject("")
	reject("   ")
	reject("\n\t")
	reject("\x00\x01")

	// 限长按 rune，多字节中文不应被截断成半个字符。
	long := strings.Repeat("字", maxTranslateQueryRunes+50)
	got, good := normalizeTranslateQuery(long)
	if !good {
		t.Fatal("long query should still be accepted after truncation")
	}
	if rc := len([]rune(got)); rc != maxTranslateQueryRunes {
		t.Fatalf("normalized rune count = %d, want %d", rc, maxTranslateQueryRunes)
	}
}

func TestStripControlRunesNoop(t *testing.T) {
	// 无控制字符的常见输入应原样返回（快速路径不分配）。
	in := "工业革命 Industrial"
	if got := stripControlRunes(in); got != in {
		t.Fatalf("stripControlRunes altered clean input: %q", got)
	}
}

func TestAppendDistinctOrderedDedupAndCap(t *testing.T) {
	seen := make(map[string]struct{})
	var list []string
	var full bool
	var stop bool

	list, stop = appendDistinctOrdered(list, seen, "a", 3)
	if stop {
		t.Fatal("single item must not report full")
	}
	list, _ = appendDistinctOrdered(list, seen, "b", 3)
	// 重复值不应增长结果集。
	list, stop = appendDistinctOrdered(list, seen, "a", 3)
	if stop || len(list) != 2 {
		t.Fatalf("duplicate should be ignored: list=%v stop=%v", list, stop)
	}
	list, full = appendDistinctOrdered(list, seen, "c", 3)
	if !full || len(list) != 3 {
		t.Fatalf("expected full at cap 3, list=%v full=%v", list, full)
	}
	// 已达上限后再追加不应突破上限。
	list, full = appendDistinctOrdered(list, seen, "d", 3)
	if len(list) != 3 {
		t.Fatalf("result exceeded cap: %v", list)
	}
	if !full {
		t.Fatal("should stay full")
	}
}

func TestAppendDistinctOrderedZeroMax(t *testing.T) {
	seen := make(map[string]struct{})
	list, stop := appendDistinctOrdered(nil, seen, "x", 0)
	if !stop || len(list) != 0 {
		t.Fatalf("max<=0 must immediately report full with no append: %v", list)
	}
}

func TestChineseSearchResultsHardCap(t *testing.T) {
	// 用内核组装结果，模拟全表命中时的累积过程：无论喂多少条，都不会超过上限。
	seen := make(map[string]struct{})
	var list []string
	stopped := false
	for i := 0; i < 500 && !stopped; i++ {
		list, stopped = appendDistinctOrdered(list, seen,
			"mod-"+itoaTen(i), maxChineseSearchResults)
	}
	if len(list) != maxChineseSearchResults {
		t.Fatalf("hard cap violated: got %d, want %d", len(list), maxChineseSearchResults)
	}
}

// itoaTen 是测试专用的简单十进制转换，避免引入 strconv 让用例保持自洽。
func itoaTen(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
