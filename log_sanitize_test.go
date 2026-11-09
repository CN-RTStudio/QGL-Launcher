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
