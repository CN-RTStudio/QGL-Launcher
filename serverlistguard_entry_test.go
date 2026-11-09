package main

import (
	"testing"
)

func TestClassifyServerHostObfuscated(t *testing.T) {
	// inet_aton 短格式 / 进制 / 单整数混淆回环必须被识别为 Loopback，
	// 而不是因只认严格四段而漏判成普通公网 IP 或域名。
	cases := []struct {
		host string
		kind ServerKind
	}{
		{"127.1", ServerKindLoopback},
		{"2130706433", ServerKindLoopback},
		{"0x7f.0.1", ServerKindLoopback},
		{"0177.0.0.1", ServerKindLoopback},
		{"::1", ServerKindLoopback},
		{"100.65.0.1", ServerKindPrivate},
		{"0x0a010203", ServerKindPrivate}, // 10.1.2.3 单整数
		{"0x08080808", ServerKindIP},      // 8.8.8.8 单整数，公网
		{"evil.example.com", ServerKindHostname},
	}
	for _, c := range cases {
		if got := classifyServerHost(c.host); got != c.kind {
			t.Fatalf("classify(%q)=%s want %s", c.host, got, c.kind)
		}
	}
}

func TestParseServerAddressLoopbackNames(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST", "localhost.", "foo.localhost", "ip6-localhost"} {
		entry, err := ParseServerAddress(host+":25565", ServerListLimits{})
		if err != nil {
			t.Fatalf("ParseServerAddress(%q) 解析失败: %v", host, err)
		}
		if entry.Kind != ServerKindLoopback {
			t.Fatalf("ParseServerAddress(%q) 分类 = %v, want loopback", host, entry.Kind)
		}
	}
}

func TestParseServerAddressIPv6Forms(t *testing.T) {
	var limDefault ServerListLimits
	lim := limDefault.withDefaults()
	valid := []struct {
		raw  string
		host string
		port int
	}{
		{"::1", "::1", 25565},
		{"[::1]", "::1", 25565},
		{"[::1]:25565", "::1", 25565},
		{"[::1]:30001", "::1", 30001},
		{"[2001:db8::1]", "2001:db8::1", 25565},
		{"[2001:db8::1]:25566", "2001:db8::1", 25566},
		{"2001:db8::1", "2001:db8::1", 25565},
	}
	for _, c := range valid {
		e, err := ParseServerAddress(c.raw, lim)
		if err != nil {
			t.Fatalf("valid %q rejected: %v", c.raw, err)
		}
		if e.Host != c.host || e.Port != c.port {
			t.Fatalf("ParseServerAddress(%q) = host=%q port=%d, want host=%q port=%d", c.raw, e.Host, e.Port, c.host, c.port)
		}
	}
	loopback, err := ParseServerAddress("::1", lim)
	if err != nil {
		t.Fatalf("valid ::1 rejected: %v", err)
	}
	if loopback.Kind != ServerKindLoopback {
		t.Fatalf("ParseServerAddress(::1) kind = %s, want loopback", loopback.Kind)
	}

	invalid := []string{
		"[::1",
		"[::1]:",
		"[::1]:0",
		"[::1]:65536",
		"[::1]:notaport",
		"[::1]x",
		"[]",
		"[]:25565",
	}
	for _, raw := range invalid {
		if _, err := ParseServerAddress(raw, lim); err == nil {
			t.Fatalf("invalid %q accepted", raw)
		}
	}
}

func TestParseServerAddressRejectsFormatRunes(t *testing.T) {
	invalid := []string{
		"evil\u0085.example.com",
		"evil\u009b.example.com",
		"evil\u202e.example.com",
		"evil\u2066.example.com",
		"evil\u200b.example.com",
		"evil\ufeff.example.com",
	}
	for _, raw := range invalid {
		if _, err := ParseServerAddress(raw, ServerListLimits{}); err == nil {
			t.Fatalf("address with format rune %q accepted", raw)
		}
	}
}

func TestSanitizeServerNameStripsFormatRunes(t *testing.T) {
	cases := map[string]string{
		"Hypixel\u202eevil":   "Hypixelevil",
		"a\u200bb":            "ab",
		"a\u0085b":            "ab",
		"a\u2066b\u2069":      "ab",
		"Hypixel archive 001": "Hypixel archive 001",
	}
	for in, want := range cases {
		if got := SanitizeServerName(in, ServerListLimits{}); got != want {
			t.Fatalf("SanitizeServerName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseServerAddressRejectsStrayColonAndSignedPort(t *testing.T) {
	invalid := []string{
		"evil.com:80:90",
		"a:b:c",
		"host:25565:25565",
		"host:+25565",
		"[::1]:+25565",
	}
	for _, raw := range invalid {
		if _, err := ParseServerAddress(raw, ServerListLimits{}); err == nil {
			t.Fatalf("invalid %q accepted", raw)
		}
	}
	valid := []string{"::1", "fe80::1", "[fe80::1]:25565", "host:025565"}
	for _, raw := range valid {
		if _, err := ParseServerAddress(raw, ServerListLimits{}); err != nil {
			t.Fatalf("valid %q rejected: %v", raw, err)
		}
	}
}
