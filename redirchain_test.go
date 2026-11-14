package main

import (
	"errors"
	"net"
	"testing"
)

var errStubNoHost = errors.New("stub resolver: host not found")

func stubResolver(m map[string][]net.IP) HostResolver {
	return func(host string) ([]net.IP, error) {
		ips, ok := m[host]
		if !ok {
			return nil, errStubNoHost
		}
		return ips, nil
	}
}

func TestRedirectChainHappy(t *testing.T) {
	chain, err := newRedirectChain("https://piston-data.mojang.com/v1/file", defaultRedirectLimits())
	if err != nil {
		t.Fatal(err)
	}
	resolve := stubResolver(map[string][]net.IP{
		"cdn.example.net": {net.ParseIP("203.0.113.9")},
	})
	ok, reason := chain.Decide("https://cdn.example.net/v1/x", resolve)
	if !ok {
		t.Fatalf("expected allow, got %s", reason)
	}
	if chain.Hops() != 2 {
		t.Fatalf("expected 2 links, got %d", chain.Hops())
	}
	// 相对路径跳转应基于上一跳解析。
	ok, reason = chain.Decide("/v1/y?a=1", resolve)
	if !ok {
		t.Fatalf("expected relative allow, got %s", reason)
	}
	last := chain.Links()[2]
	if last != "https://cdn.example.net/v1/y?a=1" {
		t.Fatalf("relative resolve mismatch: %s", last)
	}
}

func TestRedirectChainDowngrade(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	ok, reason := chain.Decide("http://mirror.example.com/f", nil)
	if ok || reason != "downgrade-to-http" {
		t.Fatalf("expected downgrade-to-http, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainAllowsHTTPWhenStaysHTTP(t *testing.T) {
	lim := defaultRedirectLimits()
	chain, _ := newRedirectChain("http://mirror.example.com/f", lim)
	ok, reason := chain.Decide("http://mirror.example.com/g", nil)
	if !ok {
		t.Fatalf("expected http->http allow when no https seen, got %s", reason)
	}
}

func TestRedirectChainNonHTTPScheme(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	for _, loc := range []string{"file:///etc/passwd", "javascript:alert(1)", "data:text/html,x", "vbscript:msgbox(1)"} {
		ok, reason := chain.Decide(loc, nil)
		if ok || reason != "non-http-scheme" {
			t.Fatalf("loc %q: expected non-http-scheme, got ok=%v reason=%s", loc, ok, reason)
		}
	}
}

func TestRedirectChainLoop(t *testing.T) {
	chain, _ := newRedirectChain("https://cdn.example.net/a", defaultRedirectLimits())
	if ok, reason := chain.Decide("https://cdn.example.net/b/", nil); !ok {
		t.Fatalf("first hop: %s", reason)
	}
	if ok, reason := chain.Decide("https://cdn.example.net/a/", nil); ok || reason != "redirect-loop" {
		t.Fatalf("expected redirect-loop, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainSelfLoop(t *testing.T) {
	chain, _ := newRedirectChain("https://cdn.example.net/a", defaultRedirectLimits())
	ok, reason := chain.Decide("https://cdn.example.net/a", nil)
	if ok || reason != "redirect-loop" {
		t.Fatalf("expected self loop, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainUserinfo(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	ok, reason := chain.Decide("https://piston-data.mojang.com@evil.com/x", nil)
	if ok || reason != "userinfo-not-allowed" {
		t.Fatalf("expected userinfo deny, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainPrivateTargets(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	for _, loc := range []string{
		"https://127.0.0.1/x",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5/x",
		"https://[::1]/x",
		"https://2130706433/x",
	} {
		ok, reason := chain.Decide(loc, nil)
		if ok || reason != "host-not-public" {
			t.Fatalf("loc %q: expected host-not-public, got ok=%v reason=%s", loc, ok, reason)
		}
	}
}
