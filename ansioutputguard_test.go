package main

import (
	"strings"
	"testing"
)

func TestStripControlSequencesRemovesSGR(t *testing.T) {
	in := "\x1b[31m[Server thread/ERROR]\x1b[0m 无法启动"
	got := stripControlSequences(in)
	want := "[Server thread/ERROR] 无法启动"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestStripControlSequencesRemovesOSCHyperlink(t *testing.T) {
	in := "点击 \x1b]8;;http://evil.example/\x1b\\这里\x1b]8;;\x1b\\ 领取"
	got := stripControlSequences(in)
	if strings.Contains(got, "evil.example") || strings.ContainsRune(got, 0x1b) {
		t.Fatalf("OSC 未清除: %q", got)
	}
	if !strings.Contains(got, "点击") || !strings.Contains(got, "领取") {
		t.Fatalf("正文被误伤: %q", got)
	}
}

func TestStripControlSequencesRemovesCSIErase(t *testing.T) {
	in := "旧内容\x1b[2J\x1b[H新内容"
	got := stripControlSequences(in)
	if got != "旧内容新内容" {
		t.Fatalf("got %q", got)
	}
}

func TestStripControlSequencesKeepsTabAndCJK(t *testing.T) {
	in := "a\tb\t中文日志\r"
	got := stripControlSequences(in)
	want := "a\tb\t中文日志"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestStripControlSequencesCapsLength(t *testing.T) {
	in := strings.Repeat("x", maxServerOutputLineChars+64)
	got := stripControlSequences(in)
	if len(got) != maxServerOutputLineChars {
		t.Fatalf("len=%d", len(got))
	}
}

func TestStripControlSequencesEmpty(t *testing.T) {
	if got := stripControlSequences(""); got != "" {
		t.Fatalf("got %q", got)
	}
}
