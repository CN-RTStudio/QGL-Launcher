package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSanitizeSnippet(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "not found", "not found"},
		{"csi color", "a\x1b[31mRED\x1b[0m b", "aRED b"},
		{"csi clear line", "x\x1b[2K\r\ny", "x y"},
		{"osc title bel", "\x1b]0;evil-title\x07prompt> ", "prompt>"},
		{"osc title st", "\x1b]0;evil-title\x1b\\done", "done"},
		{"esc two-byte", "\x1bMz", "z"},
		{"lone esc tail", "abc\x1b", "abc"},
		{"control fold", "a\r\nb\tc\x00d\x7fe", "a b c d e"},
		{"newline log injection", "ok\nFAKE-AUDIT-LINE", "ok FAKE-AUDIT-LINE"},
		{"utf8 preserved", "中\x1b[1m文 OK", "中文 OK"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeSnippet([]byte(tc.in)); got != tc.want {
				t.Errorf("sanitizeSnippet(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestSanitizeSnippetNoControlChars(t *testing.T) {
	out := sanitizeSnippet([]byte("a\x00b\x07c\x1bd\x1b[99me\n"))
	for i := 0; i < len(out); i++ {
		if out[i] < 0x20 || out[i] == 0x7f || out[i] == 0x1b {
			t.Fatalf("输出仍含控制字节 0x%02x: %q", out[i], out)
		}
	}
}

// errReader 在第一次 Read 同时返回若干字节与一个致命错误，模拟连接在读体中途重置。
type errReader struct {
	data []byte
	err  error
	done bool
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.done = true
	return n, r.err
}

func TestReadResponseSnippetTruncation(t *testing.T) {
	// 6 字节、上限 5：应截断并标记 truncated。
	snippet, truncated, err := readResponseSnippet(strings.NewReader("123456"), 5)
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	if !truncated {
		t.Errorf("期望 truncated=true")
	}
	if snippet != "12345" {
		t.Errorf("snippet=%q want 12345", snippet)
	}
}

func TestReadResponseSnippetDefaultLimit(t *testing.T) {
	snippet, truncated, err := readResponseSnippet(strings.NewReader("short"), 0)
	if err != nil || truncated {
		t.Fatalf("err=%v truncated=%v", err, truncated)
	}
	if snippet != "short" {
		t.Errorf("snippet=%q", snippet)
	}
}

func TestReadResponseSnippetLimitCeiling(t *testing.T) {
	// 传入超过天花板的上限，不应真的按该值工作；构造 65KiB 数据，天花板 64KiB 必截断。
	big := strings.Repeat("a", 65*1024)
	_, truncated, err := readResponseSnippet(strings.NewReader(big), 1<<30)
	if err != nil {
		t.Fatalf("意外错误: %v", err)
	}
	if !truncated {
		t.Errorf("超过天花板的上限应收敛并触发截断")
	}
}

func TestReadResponseSnippetReadError(t *testing.T) {
	fatal := errors.New("connection reset")
	snippet, _, err := readResponseSnippet(&errReader{data: []byte("ab"), err: fatal}, 16)
	if !errors.Is(err, fatal) {
		t.Fatalf("期望透传读体错误，got %v", err)
	}
	if snippet != "ab" {
		t.Errorf("期望带回已读前缀 ab, got %q", snippet)
	}
}

func TestFormatHTTPStatusError(t *testing.T) {
	if got := formatHTTPStatusError(502, "", false, "搜索 Mod 失败").Error(); got != "搜索 Mod 失败: HTTP 502" {
		t.Errorf("空摘要格式错误: %q", got)
	}
	got := formatHTTPStatusError(500, "internal server error", true, "搜索整合包失败").Error()
	if !strings.Contains(got, "HTTP 500") || !strings.Contains(got, "internal server error") || !strings.HasSuffix(got, "…") {
		t.Errorf("非空截断摘要格式错误: %q", got)
	}
}
