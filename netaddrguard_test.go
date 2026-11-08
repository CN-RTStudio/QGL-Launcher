package main

import "testing"

func TestNormalizeIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"0.0.0.0", "0.0.0.0", true},
		{"255.255.255.255", "255.255.255.255", true},
		{"10.0.0.1", "10.0.0.1", true},
		{"192.168.01.1", "", false}, // 前导零歧义
		{"01.2.3.4", "", false},
		{"256.1.1.1", "", false},
		{"1.2.3", "", false},
		{"1.2.3.4.5", "", false},
		{"a.2.3.4", "", false},
		{"1. 2.3.4", "", false},
		{"1..3.4", "", false},
		{"", "", false},
		{"-1.2.3.4", "", false},
	}
	for _, c := range cases {
		got, ok := NormalizeIPv4(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Fatalf("NormalizeIPv4(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseHostPortValid(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"127.0.0.1:25565", "127.0.0.1:25565"},
		{"10.0.0.1:1", "10.0.0.1:1"},
		{"mc.example.com:25565", "mc.example.com:25565"},
		{"a-b.c-d.example.org:8080", "a-b.c-d.example.org:8080"},
		{"[2001:db8::1]:25565", "[2001:db8::1]:25565"},
		{"[::1]:65535", "[::1]:65535"},
	}
	for _, c := range cases {
		got, why := ValidateHostPort(c.in)
		if why != addrRejectNone {
			t.Fatalf("ValidateHostPort(%q) rejected: %s", c.in, why)
		}
		if got != c.want {
			t.Fatalf("ValidateHostPort(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestParseHostPortInvalid(t *testing.T) {
	cases := map[string]string{
		"":                              addrRejectEmpty,
		"127.0.0.1":                     addrRejectNoPort,
		"127.0.0.1:":                    addrRejectBadPort,
		"127.0.0.1:0":                   addrRejectBadPort,
		"127.0.0.1:65536":              addrRejectBadPort,
		"127.0.0.1:abc":                 addrRejectBadPort,
		"127.0.0.1:22/x":                addrRejectPath,
		"127.0.0.1:22?x=1":              addrRejectPath,
		"http://127.0.0.1:22":           addrRejectScheme,
		"user@127.0.0.1:22":             addrRejectUserInfo,
		"127.0.0.1 :22":                 addrRejectControl,
		"127.0.0.1:22\n":                addrRejectControl,
		"999.1.1.1:22":                  addrRejectIPv4Shape,
		"1.2.3:22":                      addrRejectIPv4Shape,
		"2001:db8::1:22":                addrRejectIPv6Shape, // 裸 IPv6 无方括号
		"[2001:db8::1:22":               addrRejectIPv6Shape, // 缺右括号
		"[not-an-ip]:22":                addrRejectIPv6Shape,
		"[1.2.3.4]:22":                  addrRejectIPv6Shape, // 括号内是 IPv4
		"-bad.example.com:22":           addrRejectHostname,
		"bad-.example.com:22":           addrRejectHostname,
		"exa mple.com:22":               addrRejectControl,
		"127.0.0.1:22 ":                 addrRejectControl,
	}
	for in, wantWhy := range cases {
		got, why := ValidateHostPort(in)
		if why != wantWhy {
			t.Fatalf("ValidateHostPort(%q) why=%s want %s (got=%q)", in, why, wantWhy, got)
		}
		if got != "" {
			t.Fatalf("ValidateHostPort(%q) should not return address, got %q", in, got)
		}
	}
}

func TestHasSpaceOrControl(t *testing.T) {
	if hasSpaceOrControl("abc:123") {
		t.Fatal("normal string should not be flagged")
	}
	for _, bad := range []string{"a b", "a\tb", "a\rb", "a\nb", "a\x00b", "a\x7fb"} {
		if !hasSpaceOrControl(bad) {
			t.Fatalf("%q should be flagged as space/control", bad)
		}
	}
}
