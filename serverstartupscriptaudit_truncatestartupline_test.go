package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateStartupLineRedactsBeforeCut(t *testing.T) {
	line := strings.Repeat("x", 148) + " password=abcdefgh"
	got := truncateStartupLine(line)
	if strings.Contains(got, "abcdefgh") || strings.Contains(got, "password=ab") {
		t.Fatalf("截断前的短值未脱敏: %q", got)
	}
	if !strings.Contains(got, "[R") {
		t.Fatalf("期望脱敏标记: %q", got)
	}
}

func TestTruncateStartupLineRuneBoundary(t *testing.T) {
	line := strings.Repeat("中", 200)
	got := truncateStartupLine(line)
	body := strings.TrimSuffix(got, "...")
	if !utf8.ValidString(body) {
		t.Fatalf("截断把 UTF-8 劈开: %q", body)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("超长行未标记截断: %q", got)
	}
}

func TestTruncateStartupLineKeepsShort(t *testing.T) {
	if got := truncateStartupLine("hello"); got != "hello" {
		t.Fatalf("短行被改动: %q", got)
	}
}

func TestTruncateToRuneBoundary(t *testing.T) {
	data := []byte(strings.Repeat("中", 100))
	got := truncateToRuneBoundary(data, 50)
	if !utf8.ValidString(got) {
		t.Fatalf("字节截断劈开 UTF-8: %q", got)
	}
	if len(got) > 50 {
		t.Fatalf("超出上限: %d", len(got))
	}
	if got != strings.Repeat("中", 16) {
		t.Fatalf("未停在边界: %q", got)
	}
}
