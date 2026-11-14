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

func TestSanitizeLogRedactsUrlUserInfo(t *testing.T) {
	cases := []struct{ in, want string }{
		{`jdbc:mysql://root:Pa55w0rd@10.0.0.1:3306/db`, `jdbc:mysql://[REDACTED]@[LAN-IP]:3306/db`},
		{`redis://:s3cret@192.168.1.5:6379`, `redis://[REDACTED]@[LAN-IP]:6379`},
		{`mongodb://user:pw@47.100.1.1:27017/x`, `mongodb://[REDACTED]@47.100.1.1:27017/x`},
		{`postgres://admin:hunter2@db.internal:5432/app`, `postgres://[REDACTED]@db.internal:5432/app`},
	}
	for _, c := range cases {
		got := sanitizeLogLine(c.in)
		if got != c.want {
			t.Fatalf("in=%q\n got=%q\nwant=%q", c.in, got, c.want)
		}
		if strings.Contains(got, "Pa55w0rd") || strings.Contains(got, "s3cret") || strings.Contains(got, "hunter2") || strings.Contains(got, "user:pw") {
			t.Fatalf("credential leaked: %q", got)
		}
	}
}

func TestSanitizeLogKeepsAtSignOutsideUserInfo(t *testing.T) {
	cases := []string{
		`https://example.com/a@b normal path`,
		`mail to alice@example.com please`,
		`path /var/lib/x@y stays`,
	}
	want := []string{
		`https://example.com/a@b normal path`,
		`mail to [EMAIL] please`,
		`path /var/lib/x@y stays`,
	}
	for i, c := range cases {
		got := sanitizeLogLine(c)
		if got != want[i] {
			t.Fatalf("case %d in=%q\n got=%q\nwant=%q", i, c, got, want[i])
		}
	}
}

func TestSanitizeLogRedactsBareBearer(t *testing.T) {
	cases := []struct{ in, want string }{
		{`Bearer abcdefgh12345678`, `[REDACTED]`},
		{`Authorization: Bearer zzz`, `Authorization: [REDACTED]`},
		{`usage: bearer short`, `usage: bearer short`},
		{`sent Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcd`, `sent [REDACTED]`},
	}
	for _, c := range cases {
		got := sanitizeLogLine(c.in)
		if got != c.want {
			t.Fatalf("in=%q\n got=%q\nwant=%q", c.in, got, c.want)
		}
	}
}

func TestSanitizeLogShortSecretNeedsNonLowercase(t *testing.T) {
	kept := []string{"password=ab", "pwd=xy", "secret=test"}
	for _, in := range kept {
		if got := sanitizeLogLine(in); got != in {
			t.Fatalf("纯小写短值不应打码: %q -> %q", in, got)
		}
	}
	redacted := []string{"token=abc123", "pwd=Xy9", "secret=a_b", "api_key=k1"}
	for _, in := range redacted {
		got := sanitizeLogLine(in)
		if strings.Contains(got, "abc123") || strings.Contains(got, "Xy9") || strings.Contains(got, "a_b") || strings.Contains(got, "k1") {
			t.Fatalf("含数字/大写/符号的短凭证应打码: %q -> %q", in, got)
		}
	}
}

func TestSanitizeLogRedactsCliPasswordFlags(t *testing.T) {
	cases := []struct{ in, want, leak string }{
		{"java -jar x.jar --password abc123", "java -jar x.jar --password [REDACTED]", "abc123"},
		{"java -jar x.jar --password=abc123", "java -jar x.jar --password=[REDACTED]", "abc123"},
		{"java -jar x.jar --passwd abc123", "java -jar x.jar --passwd [REDACTED]", "abc123"},
		{"java -jar x.jar --pwd abc123", "java -jar x.jar --pwd [REDACTED]", "abc123"},
		{"java -jar x.jar --secret abc123", "java -jar x.jar --secret [REDACTED]", "abc123"},
		{"java -jar x.jar --token abc123", "java -jar x.jar --token [REDACTED]", "abc123"},
		{"java -jar x.jar --key abc123", "java -jar x.jar --key [REDACTED]", "abc123"},
		{"java -jar x.jar --accessToken abc123", "java -jar x.jar --accessToken [REDACTED]", "abc123"},
	}
	for _, c := range cases {
		got := sanitizeLogLine(c.in)
		if got != c.want {
			t.Fatalf("in=%q\n got=%q\nwant=%q", c.in, got, c.want)
		}
		if strings.Contains(got, c.leak) {
			t.Fatalf("旗标凭证泄漏: %q", got)
		}
	}
}

func TestSanitizeLogKeepsOrdinaryDoubleDashFlags(t *testing.T) {
	cases := []string{
		"java -jar x.jar --memory 4G",
		"java -jar x.jar --username steve",
		"java -jar x.jar --version",
	}
	for _, in := range cases {
		if got := sanitizeLogLine(in); got != in {
			t.Fatalf("普通旗标不应被打码: %q -> %q", in, got)
		}
	}
}

func TestSanitizeLogStripsBidiAndZeroWidth(t *testing.T) {
	cases := []struct{ in, want string }{
		{"safe\u202eEVIL", "safeEVIL"},
		{"a\u202d" + "b", "ab"},
		{"a\u2066" + "b\u2069" + "c", "abc"},
		{"zero\u200bwidth", "zerowidth"},
		{"joiner\u200dhere", "joinerhere"},
		{"bom\ufefftag", "bomtag"},
		{"word\u2060joiner", "wordjoiner"},
	}
	for _, c := range cases {
		if got := sanitizeLogLine(c.in); got != c.want {
			t.Fatalf("in=%q\n got=%q\nwant=%q", c.in, got, c.want)
		}
	}
}

func TestSanitizeLogRedactsMinecraftSessionToken(t *testing.T) {
	cases := []string{
		`{"sessionToken":"0123456789abcdef0123456789abcdef"}`,
		`{"accessToken":"0123456789abcdef0123456789abcdef"}`,
		`{"refreshToken":"0123456789abcdef0123456789abcdef"}`,
		`{"clientToken":"0123456789abcdef0123456789abcdef"}`,
		`{"xstsToken":"0123456789abcdef0123456789abcdef"}`,
	}
	for _, in := range cases {
		got := sanitizeLogLine(in)
		if strings.Contains(got, "0123456789abcdef0123456789abcdef") {
			t.Fatalf("会话凭证泄漏: %q", got)
		}
	}
}

func TestSanitizeLogKeepsUrlHomeSegment(t *testing.T) {
	cases := []string{
		"https://example.com/home/feed",
		"https://example.com/Users/feed",
	}
	for _, in := range cases {
		if got := sanitizeLogLine(in); got != in {
			t.Fatalf("URL 路径中的 home/Users 段被误删: %q -> %q", in, got)
		}
	}
}

func TestSanitizeLogRedactsLocalHomePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"path /home/alice/x.txt", "path [USER-HOME]/x.txt"},
		{`C:\Users\steve\AppData`, `[USER-HOME]\AppData`},
		{`open /Users/steve/Library`, `open [USER-HOME]/Library`},
	}
	for _, c := range cases {
		if got := sanitizeLogLine(c.in); got != c.want {
			t.Fatalf("in=%q\n got=%q\nwant=%q", c.in, got, c.want)
		}
	}
}
