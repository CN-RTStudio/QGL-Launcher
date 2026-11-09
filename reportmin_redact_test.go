package main

import (
	"strings"
	"testing"
)

func TestMinimizeJSON(t *testing.T) {
	obj := map[string]interface{}{
		"version": "1.0",
		"detail":  "C:\\Users\\bob\\mods\\a.jar 下载失败 token=abc",
		"added": []interface{}{
			map[string]interface{}{"name": "x.jar", "dir": "D:\\data\\mods"},
			map[string]interface{}{"name": "y.jar", "dir": "mods"},
		},
		"internalState": "DROP_ME",
	}
	data, dropped, err := MinimizeJSON(obj)
	if err != nil {
		t.Fatalf("MinimizeJSON error: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	s := string(data)
	if strings.Contains(s, "DROP_ME") {
		t.Fatalf("non-whitelisted field leaked: %s", s)
	}
	if strings.Contains(s, "token=abc") {
		t.Fatalf("token value leaked: %s", s)
	}
	if !strings.Contains(s, "token=[redacted]") {
		t.Fatalf("token not redacted: %s", s)
	}
	if strings.Contains(s, "C:\\Users") {
		t.Fatalf("absolute path leaked: %s", s)
	}
	if !strings.Contains(s, "\"version\":\"1.0\"") {
		t.Fatalf("whitelisted field missing: %s", s)
	}
}

func TestMinimizeJSONBudgets(t *testing.T) {
	// 数组条数预算：500 之外截断。
	big := make([]interface{}, 600)
	for i := range big {
		big[i] = map[string]interface{}{"name": "f" + strings.Repeat("x", 10)}
	}
	obj := map[string]interface{}{"added": big}
	data, _, err := MinimizeJSON(obj)
	if err != nil {
		t.Fatalf("MinimizeJSON error: %v", err)
	}
	if strings.Count(string(data), "\"name\"") > 500 {
		t.Fatalf("array not capped: %d name fields", strings.Count(string(data), "\"name\""))
	}
	// 深度预算：嵌套超过 MaxDepth 折叠。
	deep := map[string]interface{}{"detail": "x"}
	for i := 0; i < 12; i++ {
		deep = map[string]interface{}{"added": []interface{}{deep}}
	}
	obj = map[string]interface{}{"added": deep}
	data, _, err = MinimizeJSON(obj)
	if err != nil {
		t.Fatalf("deep MinimizeJSON error: %v", err)
	}
	if strings.Contains(string(data), "深度超限") == false && len(data) > 2000 {
		t.Fatalf("depth budget not enforced: %d bytes", len(data))
	}
}

func TestScrubTokenKeyMatrix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// 常见凭据键的直写形态
		{"api_key=AAAA&v=1", "api_key=[redacted]v=1"},
		{"password=hunter2", "password=[redacted]"},
		{"apikey=xyz&id=7", "apikey=[redacted]id=7"},
		{"secret=xyzzy", "secret=[redacted]"},
		{"sign=abc123", "sign=[redacted]"},
		{"key=deadbeef", "key=[redacted]"},
		// 大写键名：小写化匹配
		{"ACCESS_TOKEN=ZZZ", "ACCESS_TOKEN=[redacted]"},
		{"Token=yyy", "Token=[redacted]"},
		// 键名作为更长标识符的一部分时不得误伤（词边界）
		{"monkey=banana", "monkey=banana"},
		{"keyboard=usb", "keyboard=usb"},
		{"tokenizer=x", "tokenizer=x"},
		// 无值的空参数保持原样（实现行为：凭据键一律占位，空值同样占位）
		{"a=&token=", "a=&token=[redacted]"},
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScrubURLUserinfoMatrix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://alice:pw@host/x", "https://[redacted]host/x"},
		{"https://bob@host/x", "https://[redacted]host/x"},
		{"wss://u@h/", "wss://[redacted]h/"},
		{"no scheme user@host", "no scheme user@host"},
		{"https://host/path?k=1#frag", "https://host/path?k=1#frag"},
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScrubTerminalInjectionInValues(t *testing.T) {
	// 遥测值里的终端注入整段剥除（含 OSC、C1 CSI、孤立 ESC）。
	cases := []struct {
		in   string
		want string
	}{
		{"x\x1b]0;newname\x07y", "xy"},
		{"\x9b31mred", "red"},
		{"a\x1bb", "ab"},
		{"plain \t tab", "plain  tab"}, // 制表符随 CRLF 折叠归一为单个空格
	}
	for _, tc := range cases {
		got := ScrubTelemetryValue(tc.in)
		if got != tc.want {
			t.Fatalf("ScrubTelemetryValue(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestScrubComposedAttack(t *testing.T) {
	// 组合攻击：URL 凭据 + 查询令牌 + 长十六进制 + 本地路径 + 终端序列。
	in := "https://u:p@example.com/dl?token=ABCDEF0123456789ABCDEF0123456789ABCDEF&f=C:\\Users\\bob\\evil\x1b[31m.jar"
	got := ScrubTelemetryValue(in)
	if strings.Contains(got, "u:p@") {
		t.Fatalf("userinfo leaked: %q", got)
	}
	if strings.Contains(got, "ABCDEF0123456789") {
		t.Fatalf("long hex leaked: %q", got)
	}
	if strings.Contains(got, "\\Users\\bob") {
		t.Fatalf("local path leaked: %q", got)
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("terminal escape leaked: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("no redaction marker: %q", got)
	}
	if !strings.Contains(got, "token=[redacted]") {
		t.Fatalf("token value not redacted: %q", got)
	}
}
