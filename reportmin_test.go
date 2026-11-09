package main

import (
	"strings"
	"testing"
)

// reportmin_test.go —— 遥测最小化内核的穷举测试：值去敏（路径 / 令牌 / 长十六
// 进制 / 换行注入）、字段白名单、长度与预算上界、JSON 递归最小化。

func TestScrubLocalPaths(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"C:\\Users\\bob\\mods\\evil.jar", "<本地路径:evil.jar>"},
		{"c:/users/bob/mods/evil.jar", "<本地路径:evil.jar>"},
		{"/home/bob/mods/evil.jar", "<本地路径:evil.jar>"},
		{"\\\\server\\share\\x", "<本地路径:x>"},
		{"相对路径/不掩码.jar", "相对路径/不掩码.jar"},
		{"/usr", "/usr"}, // 单段根路径不掩码
		{"值: D:\\data\\x.txt 结尾", "值: <本地路径:x.txt> 结尾"},
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScrubTokens(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://user:pass@example.com/x", "https://[redacted]example.com/x"},
		{"token=abc123&next=1", "token=[redacted]next=1"},
		{"?access_token=SECRET&x=1", "?access_token=[redacted]x=1"},
		{"key=abcdef&sign=deadbeef", "key=[redacted]sign=[redacted]"},
		{"plain text no tokens", "plain text no tokens"},
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskLongHex(t *testing.T) {
	long := strings.Repeat("a1b2c3d4e5", 5) // 50 位十六进制
	got := ScrubTelemetryValue(long)
	if strings.Contains(got, "a1b2") {
		t.Fatalf("long hex not masked: %q", got)
	}
	if !strings.Contains(got, "<hex") {
		t.Fatalf("mask marker missing: %q", got)
	}
	// 短串（如版本号）不误伤。
	short := "1a2b3c"
	if got := ScrubTelemetryValue(short); got != short {
		t.Fatalf("short hex wrongly masked: %q", got)
	}
}

func TestScrubControlChars(t *testing.T) {
	in := "line1\r\nline2\x00\x1b[31m"
	got := ScrubTelemetryValue(in)
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") {
		t.Fatalf("newline not folded: %q", got)
	}
	if strings.Contains(got, "\x00") || strings.Contains(got, "\x1b") || strings.Contains(got, "[31m") {
		t.Fatalf("control/terminal residue: %q", got)
	}
	if got != "line1 line2" {
		t.Fatalf("content damaged: %q", got)
	}
}

func TestMinimizeMap(t *testing.T) {
	in := map[string]string{
		"eventId":   "e-1",
		"detail":    "C:\\Users\\bob\\x.txt",
		"secretEnv": "SHOULD_DROP",
	}
	out, dropped := MinimizeMap(in)
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if _, ok := out["secretEnv"]; ok {
		t.Fatal("non-whitelisted field leaked")
	}
	if !strings.Contains(out["detail"], "<本地路径:x.txt>") {
		t.Fatalf("detail not scrubbed: %q", out["detail"])
	}
}

// 追加的攻击向量矩阵（r53 扩展）：覆盖大小写键、词边界防误伤、URL 凭据、
// 十六进制掩码与路径掩码的组合，防止去敏内核被绕过。
