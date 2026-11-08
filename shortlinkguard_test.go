package main

import (
	"net"
	"testing"
)

// shortlinkguard_test.go —— 短链预检内核的穷举测试：协议白名单、私网 IP 判定
// （含混淆写法）、域名解析判定、跳数上限。全部用假 resolver，不发起真实网络。

// fakeResolver 让指定主机解析到给定 IP 列表；未登记的主机返回解析失败。
func fakeResolver(mapping map[string][]net.IP) HostResolver {
	return func(host string) ([]net.IP, error) {
		if ips, ok := mapping[host]; ok {
			return ips, nil
		}
		return nil, net.UnknownNetworkError("no such host: " + host)
	}
}

func ip(s string) net.IP { return net.ParseIP(s) }

func TestKnownShortenerHost(t *testing.T) {
	yes := []string{"bit.ly", "www.t.cn", "tinyurl.com", "t.CO", "Bit.Ly", "dwz.cn"}
	for _, h := range yes {
		if !knownShortenerHost(h) {
			t.Fatalf("knownShortenerHost(%q) = false, want true", h)
		}
	}
	no := []string{"example.com", "localhost", "", "bit.ly.evil.com", "notbitly.com"}
	for _, h := range no {
		if knownShortenerHost(h) {
			t.Fatalf("knownShortenerHost(%q) = true, want false", h)
		}
	}
}

func TestIsShortLinkURL(t *testing.T) {
	if !isShortLinkURL("https://t.cn/abc") {
		t.Fatal("t.cn should be a short link")
	}
	if isShortLinkURL("https://example.com/x") {
		t.Fatal("example.com should not be a short link")
	}
	if isShortLinkURL("") {
		t.Fatal("empty should not be a short link")
	}
}

func TestNormalizeScheme(t *testing.T) {
	// 合法 https。
	if _, err := normalizeScheme("https://example.com/x"); err != nil {
		t.Fatalf("https rejected: %v", err)
	}
	// http 明文拒绝。
	if _, err := normalizeScheme("http://example.com/x"); err == nil {
		t.Fatal("http should be rejected")
	}
	// 危险协议拒绝。
	for _, p := range []string{"file:///etc/passwd", "javascript:alert(1)", "data:text/html,<b>x", "vbscript:x"} {
		if _, err := normalizeScheme(p); err == nil {
			t.Fatalf("protocol %q should be rejected", p)
		}
	}
	// userinfo 拒绝。
	if _, err := normalizeScheme("https://user:pass@example.com/x"); err == nil {
		t.Fatal("userinfo should be rejected")
	}
	// 空 / 无法解析。
	if _, err := normalizeScheme("   "); err == nil {
		t.Fatal("empty should be rejected")
	}
	if _, err := normalizeScheme("://bad"); err == nil {
		t.Fatal("unparseable should be rejected")
	}
}

func TestVerdictForHost(t *testing.T) {
	noResolve := HostResolver(nil)
	// IP 字面量私网判定（不需要 resolver）。
	private := []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.1",
		"169.254.169.254", "0.0.0.0", "::1", "fe80::1", "2130706433", // 十进制混淆 127.0.0.1
	}
	for _, h := range private {
		if v := verdictForHost(h, noResolve); !v.Blocked {
			t.Fatalf("private host %q not blocked", h)
		}
	}
	// 公网 IP 字面量放行。
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}
	for _, h := range public {
		if v := verdictForHost(h, noResolve); v.Blocked {
			t.Fatalf("public host %q blocked: %s", h, v.Reason)
		}
	}
	// 无 resolver 的域名：宁严勿纵。
	if v := verdictForHost("example.com", noResolve); !v.Blocked {
		t.Fatal("domain without resolver should be blocked")
	}
	// resolver 解析到私网：拒绝。
	bad := fakeResolver(map[string][]net.IP{"internal.example": {ip("10.1.2.3"), ip("8.8.8.8")}})
	if v := verdictForHost("internal.example", bad); !v.Blocked {
		t.Fatal("mixed private/public resolution should be blocked")
	}
	// resolver 解析到公网：放行。
	good := fakeResolver(map[string][]net.IP{"public.example": {ip("8.8.8.8"), ip("1.1.1.1")}})
	if v := verdictForHost("public.example", good); v.Blocked {
		t.Fatalf("public domain blocked: %s", v.Reason)
	}
	// 解析失败：拒绝。
	fail := fakeResolver(map[string][]net.IP{})
	if v := verdictForHost("ghost.example", fail); !v.Blocked {
		t.Fatal("unresolvable domain should be blocked")
	}
}

func TestPreflightShortLink(t *testing.T) {
	resolve := fakeResolver(map[string][]net.IP{
		"public.example": {ip("8.8.8.8")},
		"t.cn":           {ip("8.8.8.8")}, // 短链域本身解析到公网
	})

	// 短链 + 公网目标：放行。
	raw := "https://t.cn/abc"
	if _, err := preflightShortLink(raw, 0, resolve); err != nil {
		t.Fatalf("public short link rejected: %v", err)
	}
	// 短链 + 私网目标：拒绝。
	raw = "https://t.cn/x"
	priv := fakeResolver(map[string][]net.IP{"t.cn": {ip("127.0.0.1")}})
	if _, err := preflightShortLink(raw, 0, priv); err == nil {
		t.Fatal("short link to loopback should be rejected")
	}
	// 非短链 https 公网 URL：只做协议校验，原样通过。
	if _, err := preflightShortLink("https://example.com/x", 0, nil); err != nil {
		t.Fatalf("plain https rejected: %v", err)
	}
	// 非短链 http：拒绝。
	if _, err := preflightShortLink("http://example.com/x", 0, nil); err == nil {
		t.Fatal("plain http should be rejected")
	}
	// 跳数越界：拒绝。
	if _, err := preflightShortLink("https://t.cn/abc", maxRedirectHops+1, resolve); err == nil {
		t.Fatal("hop overrun should be rejected")
	}
	// 负数跳数：拒绝。
	if _, err := preflightShortLink("https://t.cn/abc", -1, resolve); err == nil {
		t.Fatal("negative hops should be rejected")
	}
}

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

// TestKnownShortenerHostTrailingDot 覆盖 FQDN 尾点写法：`bit.ly.` 与 `bit.ly`
// 指向同一台主机，旧实现查表不命中，整条短链通道就被跳过。
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

// TestIsShortLinkURLHostNormalisation 覆盖「短链 + 显式端口 / 尾点」的识别：
// 旧实现拿 u.Host（含端口）去比较，`bit.ly:443` 与 `bit.ly.` 都不在表里。
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

// TestNormalizeSchemeRejectsStructure 覆盖「结构签证」：空主机、空 authority 带
// 端口、不透明形式、fragment、百分号编码主机都必须在预检阶段判死。
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

// TestPreflightDownloadURLRejectsHostless 是下载入口的回归：`https://` 与
// `https://:443/x` 曾经原样放行，调用方会把它当合法地址继续落库。
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

// TestShortLinkPortBypassClosed 是本轮的核心回归：短链域加 `:443` 后缀后，
// 旧实现不再把它识别为短链，于是整段私网判定被跳过。
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

// TestGuardRedirectTargetPort 覆盖「目标域名带端口」：旧实现把 `host:port`
// 整串交给 resolver，解析必然失败，合法跳转被误杀。
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
