package main

import (
	"strings"
	"testing"
)

func TestParseServerAddress(t *testing.T) {
	var lim0 ServerListLimits
	lim := lim0.withDefaults()

	cases := []struct {
		raw  string
		ok   bool
		host string
		port int
		kind ServerKind
	}{
		{"play.example.com", true, "play.example.com", 25565, ServerKindHostname},
		{"mc.hypixel.net:25565", true, "mc.hypixel.net", 25565, ServerKindHostname},
		{"127.0.0.1:30001", true, "127.0.0.1", 30001, ServerKindLoopback},
		{"192.168.1.10", true, "192.168.1.10", 25565, ServerKindPrivate},
		{"10.0.0.2:19132", true, "10.0.0.2", 19132, ServerKindPrivate},
		{"[::1]:25565", true, "::1", 25565, ServerKindLoopback},
		{"8.8.8.8:53", true, "8.8.8.8", 53, ServerKindIP},
	}
	for _, c := range cases {
		e, err := ParseServerAddress(c.raw, lim)
		if err != nil {
			t.Fatalf("valid %q rejected: %v", c.raw, err)
		}
		if e.Host != c.host || e.Port != c.port || e.Kind != c.kind {
			t.Fatalf("ParseServerAddress(%q) = %+v want host=%s port=%d kind=%s", c.raw, e, c.host, c.port, c.kind)
		}
	}

	invalid := []string{
		"",
		" ",
		"evil.com; rm -rf /",
		"https://evil.com",
		"mc://evil.com",
		"evil.com:notaport",
		"evil.com:0",
		"evil.com:65536",
		"evil.com:",
		"evil.com/path",
		"evil.com\\path",
		"evil.com,backup.com",
		"\"evil.com\"",
		"evil.com\n",
		"a b.com",
	}
	for _, raw := range invalid {
		if _, err := ParseServerAddress(raw, lim); err == nil {
			t.Fatalf("invalid %q accepted", raw)
		}
	}
}

func TestServerListSanitizeName(t *testing.T) {
	var lim0 ServerListLimits
	lim := lim0.withDefaults()
	if got := SanitizeServerName("  Hello World  ", lim); got != "Hello World" {
		t.Fatalf("trim failed: %q", got)
	}
	if got := SanitizeServerName("bad\u0001name\u009f", lim); got != "badname" {
		t.Fatalf("control char strip failed: %q", got)
	}
	long := strings.Repeat("x", 200)
	if got := SanitizeServerName(long, lim); len([]rune(got)) != 96 {
		t.Fatalf("length limit failed: %d", len([]rune(got)))
	}
	// C1 控制区 (U+0080-U+009F) 也要剥干净，不可见字符不能残留进列表名。
	if got := SanitizeServerName("a\u0080b\u009fc", lim); got != "abc" {
		t.Fatalf("C1 control strip failed: %q", got)
	}
}

func TestParseServerListText(t *testing.T) {
	var lim0 ServerListLimits
	lim := lim0.withDefaults()

	text := strings.Join([]string{
		"# comment line",
		"Hypixel mc.hypixel.net:25565",
		"LAN Server 192.168.1.5:25565",
		"bad evil.com;rm -rf /",
		"",
		"Direct|play.example.com",
	}, "\n")
	entries, errs := ParseServerListText(text, lim)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d (errs=%v)", len(entries), errs)
	}
	if entries[0].Name != "Hypixel" || entries[0].Host != "mc.hypixel.net" {
		t.Fatalf("entry0 wrong: %+v", entries[0])
	}
	if entries[2].Name != "Direct" {
		t.Fatalf("pipe split failed: %+v", entries[2])
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(errs), errs)
	}
}

func TestClassifyServerHost(t *testing.T) {
	cases := []struct {
		host string
		kind ServerKind
	}{
		{"example.com", ServerKindHostname},
		{"127.0.0.1", ServerKindLoopback},
		{"127.8.9.10", ServerKindLoopback},
		{"::1", ServerKindLoopback},
		{"192.168.0.1", ServerKindPrivate},
		{"10.1.2.3", ServerKindPrivate},
		{"172.16.0.1", ServerKindPrivate},
		{"172.32.0.1", ServerKindIP},
		{"169.254.10.10", ServerKindPrivate},
		{"8.8.8.8", ServerKindIP},
	}
	for _, c := range cases {
		if got := classifyServerHost(c.host); got != c.kind {
			t.Fatalf("classify(%q)=%s want %s", c.host, got, c.kind)
		}
	}
}

func TestSummarizeServerEntries(t *testing.T) {
	s := SummarizeServerEntries([]ServerEntry{{Host: "a"}}, nil)
	if !strings.Contains(s, "serverlist parsed entries=1") {
		t.Fatalf("unexpected summary: %q", s)
	}
	s2 := SummarizeServerEntries(nil, []string{"x"})
	if !strings.Contains(s2, "errors=1") {
		t.Fatalf("unexpected summary: %q", s2)
	}
}

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
