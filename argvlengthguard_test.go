package main

import (
	"strings"
	"testing"
)

func TestCommandLineChars(t *testing.T) {
	if got := commandLineChars(nil); got != 0 {
		t.Fatalf("nil argv chars = %d, want 0", got)
	}
	if got := commandLineChars([]string{}); got != 0 {
		t.Fatalf("empty argv chars = %d, want 0", got)
	}
	if got := commandLineChars([]string{"java"}); got != 4 {
		t.Fatalf("single arg chars = %d, want 4", got)
	}
	// "java -version" -> 13 个字符，中间恰好一个空格。
	if got := commandLineChars([]string{"java", "-version"}); got != 13 {
		t.Fatalf("two arg chars = %d, want 13", got)
	}
	// 多字节字符按码点计数：每个中文算 1 个字符、3 个字节。
	if got := commandLineChars([]string{"中", "文"}); got != 3 {
		t.Fatalf("unicode chars = %d, want 3 (two runes + space)", got)
	}
}

func TestLongestArgIndex(t *testing.T) {
	if got := longestArgIndex(nil); got != -1 {
		t.Fatalf("nil longest = %d, want -1", got)
	}
	argv := []string{"java", "-cp", "aaa;bbb;ccc", "-Xmx2G"}
	if got := longestArgIndex(argv); got != 2 {
		t.Fatalf("longest index = %d, want 2", got)
	}
	// 平手时保留最先出现的位置。
	if got := longestArgIndex([]string{"ab", "cd"}); got != 0 {
		t.Fatalf("tie longest index = %d, want 0", got)
	}
}

func TestArgvLengthReport(t *testing.T) {
	r := argvLengthReportFor([]string{"java", "-version"})
	if r.Argc != 2 || r.Chars != 13 || r.Limit != createProcessCommandLineMaxChars {
		t.Fatalf("unexpected small report: %+v", r)
	}
	if r.Over {
		t.Fatalf("short command line must not be over limit")
	}
	if r.Longest != 1 {
		t.Fatalf("longest arg = %d, want 1 (-version)", r.Longest)
	}
	if headroomFor([]string{"java"}) != createProcessCommandLineMaxChars-4 {
		t.Fatalf("headroom mismatch for short argv")
	}
}

func TestArgvLengthReportOverLimit(t *testing.T) {
	// 构造一条超过 32767 字符的 classpath，模拟几十个超长 jar 路径相加。
	long := "-cp=" + strings.Repeat("C:\\libs\\a.jar;", 2400)
	argv := []string{"java", long, "net.minecraft.client.main.Main"}
	r := argvLengthReportFor(argv)
	if !r.Over {
		t.Fatalf("expected over-limit command line, chars=%d", r.Chars)
	}
	if r.Longest != 1 {
		t.Fatalf("classpath should be longest arg, got %d", r.Longest)
	}
	if headroomFor(argv) >= 0 {
		t.Fatalf("headroom must be negative when over limit")
	}
}

func TestArgvLengthReportAtExactBoundary(t *testing.T) {
	// 单参数恰好等于上限：不超（chars == limit）。
	exact := strings.Repeat("a", createProcessCommandLineMaxChars)
	r := argvLengthReportFor([]string{exact})
	if r.Over {
		t.Fatalf("command line exactly at limit must not be over, chars=%d", r.Chars)
	}
	// 再加一个参数引入空格 + 一个字符，立刻超限。
	r2 := argvLengthReportFor([]string{exact, "b"})
	if !r2.Over {
		t.Fatalf("one char past limit must be over, chars=%d", r2.Chars)
	}
}
