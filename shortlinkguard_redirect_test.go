package main

import (
	"net"
	"testing"
)

func TestPreflightRedirectHop(t *testing.T) {
	resolve := fakeResolver(map[string][]net.IP{"public.example": {ip("8.8.8.8")}})
	// 第 1 跳公网：放行。
	if err := preflightRedirectHop("https://public.example/final", 1, resolve); err != nil {
		t.Fatalf("public hop rejected: %v", err)
	}
	// 超上限跳数：拒绝。
	if err := preflightRedirectHop("https://public.example/final", maxRedirectHops+1, resolve); err == nil {
		t.Fatal("hop overrun should be rejected")
	}
	// 目标私网：拒绝。
	priv := fakeResolver(map[string][]net.IP{"meta.example": {ip("169.254.169.254")}})
	if err := preflightRedirectHop("https://meta.example/x", 1, priv); err == nil {
		t.Fatal("private hop should be rejected")
	}
	// 非 https：拒绝。
	if err := preflightRedirectHop("http://public.example/x", 1, resolve); err == nil {
		t.Fatal("http hop should be rejected")
	}
}

func TestPreflightDownloadURL(t *testing.T) {
	// 下载入口默认走真实 DNS 解析器——这里只测协议层行为（非短链不解析）。
	if _, err := preflightDownloadURL("https://example.com/file.zip", nil); err != nil {
		t.Fatalf("plain https download rejected: %v", err)
	}
	if _, err := preflightDownloadURL("http://example.com/file.zip", nil); err == nil {
		t.Fatal("http download should be rejected")
	}
	if _, err := preflightDownloadURL("file:///etc/passwd", nil); err == nil {
		t.Fatal("file download should be rejected")
	}
	// 注入自定义 resolver 后，短链到私网必须被拦。
	priv := fakeResolver(map[string][]net.IP{"t.cn": {ip("10.0.0.1")}})
	if _, err := preflightDownloadURL("https://t.cn/zip", priv); err == nil {
		t.Fatal("short link to private should be rejected at download entry")
	}
}

func TestKnownShortenerHostTrailingDot(t *testing.T) {
	for _, h := range []string{"bit.ly.", "www.t.cn.", "TINYURL.COM..", " bit.ly. "} {
		if !knownShortenerHost(h) {
			t.Fatalf("knownShortenerHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{".", "..", "bit.ly.evil.com.", "evilbit.ly."} {
		if knownShortenerHost(h) {
			t.Fatalf("knownShortenerHost(%q) = true, want false", h)
		}
	}
}

func TestIsShortLinkURLHostNormalisation(t *testing.T) {
	yes := []string{
		"https://bit.ly:443/abc",
		"https://bit.ly./abc",
		"https://www.t.cn:8443/x",
		"  https://T.CN/a  ",
	}
	for _, raw := range yes {
		if !isShortLinkURL(raw) {
			t.Fatalf("isShortLinkURL(%q) = false, want true", raw)
		}
	}
	no := []string{
		"https://bit.ly.evil.com:443/x",
		"https://bitly.com/x",
		"https://example.com:443/bit.ly",
		"",
	}
	for _, raw := range no {
		if isShortLinkURL(raw) {
			t.Fatalf("isShortLinkURL(%q) = true, want false", raw)
		}
	}
}

func TestNormalizeSchemeRejectsStructure(t *testing.T) {
	bad := []string{
		"https://",
		"https://:443/x",
		"https:opaque",
		"https://example.com/a.zip#frag",
		"https://%31%32%37.0.0.1/a.zip",
		"https://user@example.com/x",
	}
	for _, raw := range bad {
		if _, err := normalizeScheme(raw); err == nil {
			t.Fatalf("normalizeScheme(%q) accepted, want rejection", raw)
		}
	}
	// 正常 https 仍然放行，且返回的是规范形式（无 fragment / 无 userinfo）。
	out, err := normalizeScheme("  https://example.com/a.zip  ")
	if err != nil {
		t.Fatalf("plain https rejected: %v", err)
	}
	if out != "https://example.com/a.zip" {
		t.Fatalf("normalizeScheme output = %q", out)
	}
}

func TestPreflightDownloadURLRejectsHostless(t *testing.T) {
	for _, raw := range []string{"https://", "https://:443/x", "https:///x"} {
		if _, err := preflightDownloadURL(raw, nil); err == nil {
			t.Fatalf("hostless URL %q accepted at download entry", raw)
		}
	}
	// fragment 不参与真实请求，保留它只会让审计日志看到与请求不同的地址。
	if _, err := preflightDownloadURL("https://example.com/a.zip#frag", nil); err == nil {
		t.Fatal("fragment URL accepted at download entry")
	}
}

func TestShortLinkPortBypassClosed(t *testing.T) {
	priv := fakeResolver(map[string][]net.IP{
		"bit.ly": {ip("169.254.169.254")},
		"t.cn":   {ip("127.0.0.1")},
	})
	for _, raw := range []string{
		"https://bit.ly:443/abc",
		"https://bit.ly./abc",
		"https://bit.ly:8443/abc",
	} {
		if _, err := preflightDownloadURL(raw, priv); err == nil {
			t.Fatalf("private short link %q accepted", raw)
		}
	}
	// 短链域解析到公网时仍然放行（端口不影响目标判定）。
	pub := fakeResolver(map[string][]net.IP{"bit.ly": {ip("8.8.8.8")}})
	norm, err := preflightDownloadURL("https://bit.ly:443/abc", pub)
	if err != nil {
		t.Fatalf("public short link with port rejected: %v", err)
	}
	if norm != "https://bit.ly:443/abc" {
		t.Fatalf("normalised short link = %q", norm)
	}
}

func TestGuardRedirectTargetPort(t *testing.T) {
	resolve := fakeResolver(map[string][]net.IP{"public.example": {ip("8.8.8.8")}})
	if v := guardRedirectTarget("https://public.example:443/final", resolve); v.Blocked {
		t.Fatalf("public target with port blocked: %s", v.Reason)
	}
	if v := guardRedirectTarget("https://public.example/x", resolve); v.Blocked {
		t.Fatalf("public target blocked: %s", v.Reason)
	}
	priv := fakeResolver(map[string][]net.IP{"public.example": {ip("10.0.0.1")}})
	if v := guardRedirectTarget("https://public.example:443/final", priv); !v.Blocked {
		t.Fatal("private target with port not blocked")
	}
	if v := guardRedirectTarget("https:///x", resolve); !v.Blocked {
		t.Fatal("hostless target not blocked")
	}
}
