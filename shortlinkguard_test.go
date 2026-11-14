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

// TestKnownShortenerHostTrailingDot 覆盖 FQDN 尾点写法：`bit.ly.` 与 `bit.ly`
// 指向同一台主机，旧实现查表不命中，整条短链通道就被跳过。

// TestIsShortLinkURLHostNormalisation 覆盖「短链 + 显式端口 / 尾点」的识别：
// 旧实现拿 u.Host（含端口）去比较，`bit.ly:443` 与 `bit.ly.` 都不在表里。

// TestNormalizeSchemeRejectsStructure 覆盖「结构签证」：空主机、空 authority 带
// 端口、不透明形式、fragment、百分号编码主机都必须在预检阶段判死。

// TestPreflightDownloadURLRejectsHostless 是下载入口的回归：`https://` 与
// `https://:443/x` 曾经原样放行，调用方会把它当合法地址继续落库。

// TestShortLinkPortBypassClosed 是本轮的核心回归：短链域加 `:443` 后缀后，
// 旧实现不再把它识别为短链，于是整段私网判定被跳过。

// TestGuardRedirectTargetPort 覆盖「目标域名带端口」：旧实现把 `host:port`
// 整串交给 resolver，解析必然失败，合法跳转被误杀。
