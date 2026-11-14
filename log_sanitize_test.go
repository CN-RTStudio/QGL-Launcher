package main

import (
	"strings"
	"testing"
)

func TestSanitizeLogRedactsAccessTokenForms(t *testing.T) {
	cases := []struct{ name, in string }{
		{"query", "POST /login access_token=eyJhbGciOiJIUzI1NiJ9WXYZabcdef.ok done"},
		{"equals spaced", "accessToken =   eyAbCdEfGhIjKlMnOpQrStUvWxYz0123456789 end"},
		{"json", `{"accessToken":"M.R3_AUTH_1234567890abcdefghijklmnop"}`},
		{"json spaced", `"refresh_token": "RtE9x8v7n6m5b4v3c2z1a0s9d8f7g6h5j4k3l2m1"`},
		{"session id", "sid session=abcdef0123456789ABCDEF logged"},
		{"client secret", "client_secret=6d41d8cd98f00b204e9800998ecf8427e"},
		{"api key", `X-Api-Key: AKIA1234567890ABCDEF`},
		{"password", "login password=hunter2hunter2 ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := sanitizeLogLine(c.in)
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("敏感值未被打码: in=%q out=%q", c.in, out)
			}
			// 原始凭证本体不应残留：提取若干特征片段确认被抹掉。
			for _, leak := range []string{"M.R3_AUTH_1234567890", "AKIA1234567890ABCDEF", "hunter2hunter2"} {
				if strings.Contains(c.in, leak) && strings.Contains(out, leak) {
					t.Errorf("原始凭证残留在日志中: %q", leak)
				}
			}
		})
	}
}

func TestSanitizeLogRedactsBearerAndJWT(t *testing.T) {
	if got := sanitizeLogLine("Authorization: Bearer mF_9.B5f-4.1JqM/abc123DEF456"); !strings.Contains(got, "[REDACTED]") ||
		strings.Contains(got, "abc123DEF456") {
		t.Errorf("Bearer token 未脱敏: %q", got)
	}
	jwt := "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0WP8qZ9Z9Z9Z9Z9Z9Z9Z9Z9"
	if got := sanitizeLogLine(jwt); !strings.Contains(got, "[JWT]") {
		t.Errorf("裸 JWT 未脱敏: %q", got)
	}
}

func TestSanitizeLogKeepsBenignText(t *testing.T) {
	benign := []string{
		"正在下载 https://launcher.example.com/v1/packages/abc",
		"Forge 47.2.0 安装完成，耗时 12.3s",
		`设置环境变量 JAVA_HOME=C:\Program Files\Java\jdk-17`,
		"加载 mod 数量: 42，失败 0",
	}
	for _, in := range benign {
		if got := sanitizeLogLine(in); got != in {
			t.Errorf("普通日志不应被改写: in=%q out=%q", in, got)
		}
	}
}

func TestSanitizeLogRedactsEmailUUIDAndLANIP(t *testing.T) {
	in := "user mail test.user@example.com uuid 123e4567-e89b-12d3-a456-426614174000 from 192.168.10.23"
	out := sanitizeLogLine(in)
	for _, want := range []string{"[EMAIL]", "[UUID]", "[LAN-IP]"} {
		if !strings.Contains(out, want) {
			t.Errorf("期望包含 %s，实际 %q", want, out)
		}
	}
	if strings.Contains(out, "192.168.10.23") {
		t.Errorf("内网 IP 未脱敏: %q", out)
	}
}

func TestSanitizeLogShortValuesAreLeftAlone(t *testing.T) {
	// 过短的值（<6）不按敏感键打码，避免误伤普通说明文字。
	in := "password=ab"
	if got := sanitizeLogLine(in); got != in {
		t.Errorf("短值不应被规则误伤: %q -> %q", in, got)
	}
}

func TestSanitizeLogRedactsBasicAuthAndCookie(t *testing.T) {
	basic := "Authorization: Basic dXNlcjpwYXNzd29yZA=="
	if got := sanitizeLogLine(basic); strings.Contains(got, "dXNlcjpwYXNzd29yZA") {
		t.Errorf("Basic 凭据未脱敏: %q", got)
	}
	cookie := "Cookie: session=abcdef0123456789; theme=dark"
	if got := sanitizeLogLine(cookie); strings.Contains(got, "abcdef0123456789") {
		t.Errorf("Cookie 会话值未脱敏: %q", got)
	}
}

func TestSanitizeLogLineRedactsCLIFlagCredentials(t *testing.T) {
	cases := []struct {
		in   string
		leak string
	}{
		{"java -jar server.jar --accessToken abcdef123456", "abcdef123456"},
		{"java -jar server.jar --sessionId=99887766", "99887766"},
		{"java -jar server.jar --clientSecret s3cr3t-value", "s3cr3t-value"},
	}
	for _, c := range cases {
		out := sanitizeLogLine(c.in)
		if strings.Contains(out, c.leak) {
			t.Fatalf("命令行凭据未脱敏: %q -> %q", c.in, out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("缺少脱敏占位: %q -> %q", c.in, out)
		}
	}
	out := sanitizeLogLine("java -jar server.jar --username Steve --maxMemory 2G")
	if !strings.Contains(out, "Steve") || !strings.Contains(out, "2G") {
		t.Fatalf("非敏感参数被误伤: %q", out)
	}
}

func TestSanitizeLogRedactsIPv6PrivateRanges(t *testing.T) {
	cases := []struct{ in, leak string }{
		{"peer fe80::1a2b:3c4d joined", "3c4d"},
		{"ula fd12:3456:789a:0:0:0:0:1", "3456"},
		{"host fc00::abcd up", "abcd"},
		{"loopback at ::1 port", "::1"},
	}
	for _, c := range cases {
		out := sanitizeLogLine(c.in)
		if strings.Contains(out, c.leak) {
			t.Fatalf("IPv6 私网未完整脱敏: %q -> %q", c.in, out)
		}
		if !strings.Contains(out, "[LAN-IP]") {
			t.Fatalf("缺少占位: %q -> %q", c.in, out)
		}
	}
	for _, c := range []string{"time 12::34 tick", "203.0.113.9 public", "fe80x not an address"} {
		if out := sanitizeLogLine(c); strings.Contains(out, "[LAN-IP]") {
			t.Fatalf("非私网输入被误伤: %q -> %q", c, out)
		}
	}
}

func TestSanitizeLogStripsAnsiAndControlChars(t *testing.T) {
	cases := []struct{ in, want string }{
		{"\x1b[2J\x1b[31mbad color\x1b[0m tail", "bad color tail"},
		{"\x1b]52;c;Y2xpcGJvYXJk\x07osc tail", "osc tail"},
		{"ctrl\x01char\x7fdel end", "ctrlchardel end"},
		{"\x1b[1;33mloading\x1b[0m\x1b[?25l", "loading"},
	}
	for _, c := range cases {
		out := sanitizeLogLine(c.in)
		if out != c.want {
			t.Fatalf("转义剥离不符: %q -> %q (want %q)", c.in, out, c.want)
		}
		if strings.ContainsAny(out, "\x1b\x07") {
			t.Fatalf("残留转义字节: %q", out)
		}
	}
	if out := sanitizeLogLine("plain line ok"); out != "plain line ok" {
		t.Fatalf("普通行被改动: %q", out)
	}
}

func TestSanitizeLogRedactsUserHomePaths(t *testing.T) {
	cases := []struct{ in, want string }{
		{`mc root: C:\Users\张三\AppData\Roaming\.minecraft`, `mc root: [USER-HOME]\AppData\Roaming\.minecraft`},
		{`cfg /home/alice/.minecraft/launcher_profiles.json`, `cfg [USER-HOME]/.minecraft/launcher_profiles.json`},
		{`mac /Users/bob/Library/Application Support/minecraft`, `mac [USER-HOME]/Library/Application Support/minecraft`},
	}
	for _, c := range cases {
		if out := sanitizeLogLine(c.in); out != c.want {
			t.Fatalf("家目录脱敏不符: %q -> %q (want %q)", c.in, out, c.want)
		}
	}
}

func TestSanitizeLogRedactsMappedIPv6AndReservedV4(t *testing.T) {
	cases := []struct{ in, want string }{
		{`mapped ::ffff:192.168.1.10:25565`, `mapped ::ffff:[LAN-IP]:25565`},
		{`cgnat 100.64.0.1`, `cgnat [LAN-IP]`},
		{`bench 198.18.0.5`, `bench [LAN-IP]`},
		{`zero 0.0.0.0`, `zero [LAN-IP]`},
	}
	for _, c := range cases {
		if out := sanitizeLogLine(c.in); out != c.want {
			t.Fatalf("保留网段脱敏不符: %q -> %q (want %q)", c.in, out, c.want)
		}
	}
	if out := sanitizeLogLine(`public 8.8.8.8 stays`); out != `public 8.8.8.8 stays` {
		t.Fatalf("公网地址被误伤: %q", out)
	}
}
