package main

import (
	"strings"
	"testing"
)

func TestStripLogControlChars(t *testing.T) {
	in := "a\x00b\x07c\x1bd\r\te\nf\x7fg"
	out := stripLogControlChars(in)
	for _, bad := range []string{"\x00", "\x07", "\x1b", "\r", "\n", "\x7f"} {
		if strings.Contains(out, bad) {
			t.Fatalf("控制字符 %q 未剥离: %q", bad, out)
		}
	}
	if !strings.Contains(out, "\t") {
		t.Fatal("制表符应保留")
	}
	if !strings.Contains(out, "abc") || !strings.Contains(out, "efg") {
		t.Fatalf("正常字符被误删: %q", out)
	}
}

func TestBoundCrashContextLineShort(t *testing.T) {
	in := "普通短行 no control"
	if got := boundCrashContextLine(in); got != in {
		t.Fatalf("短行应原样返回: %q", got)
	}
}

func TestBoundCrashContextLineLong(t *testing.T) {
	in := strings.Repeat("L", maxGameLogUILineBytes+500)
	got := boundCrashContextLine(in)
	if len(got) > maxGameLogUILineBytes {
		t.Fatalf("裁剪后长度 %d 仍超单行 UI 上限 %d", len(got), maxGameLogUILineBytes)
	}
	if !strings.HasSuffix(got, gameLogTruncateMarker) {
		t.Fatalf("应追加截断标记: %q", got[len(got)-20:])
	}
}

func TestBuildCrashContextKeepsTail(t *testing.T) {
	// 超过行数上限时，应保留靠后的行（崩溃看结尾）。
	var lines []string
	for i := 0; i < maxCrashContextLines+15; i++ {
		lines = append(lines, "line"+itoa64(int64(i)))
	}
	out := buildCrashContext(lines)
	rows := strings.Split(out, "\n")
	if len(rows) > maxCrashContextLines {
		t.Fatalf("行数 %d 超过上限 %d", len(rows), maxCrashContextLines)
	}
	last := "line" + itoa64(int64(maxCrashContextLines+14))
	if rows[len(rows)-1] != last {
		t.Fatalf("应保留最后一行 %s，实际末行 %s", last, rows[len(rows)-1])
	}
	// 最早的行必须被丢弃。
	if strings.Contains(out, "line0\n") {
		t.Fatal("超行数上限时不应保留最早的行")
	}
}

func TestBuildCrashContextAggregateByteBudget(t *testing.T) {
	// 每行约 1KiB，给 40 行 => 40KiB，超过 16KiB 聚合预算，只应保留结尾若干行。
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, strings.Repeat("x", 1<<10))
	}
	out := buildCrashContext(lines)
	if len(out) > maxCrashContextBytes {
		t.Fatalf("聚合上下文 %d 字节超过预算 %d", len(out), maxCrashContextBytes)
	}
	if strings.Count(out, "\n")+1 >= 40 {
		t.Fatal("聚合预算应让更早的行被丢弃")
	}
}

func TestBuildCrashContextEmpty(t *testing.T) {
	if got := buildCrashContext(nil); got != "" {
		t.Fatalf("空输入应返回空串，实际 %q", got)
	}
}

func TestBuildCrashContextOrderPreserved(t *testing.T) {
	lines := []string{"first", "second", "third"}
	out := buildCrashContext(lines)
	if out != "first\nsecond\nthird" {
		t.Fatalf("时间顺序必须保持正序: %q", out)
	}
}

func TestBuildCrashContextStripsControl(t *testing.T) {
	out := buildCrashContext([]string{"a\x00b", "c\x1bd"})
	if strings.ContainsAny(out, "\x00\x1b") {
		t.Fatalf("崩溃上下文中仍含控制字符: %q", out)
	}
}
