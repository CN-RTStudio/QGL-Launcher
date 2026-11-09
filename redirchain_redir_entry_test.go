package main

import (
	"net"
	"testing"
)

func TestRedirectChainHostPrivateByDNS(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	resolve := stubResolver(map[string][]net.IP{
		"evil.example.net": {net.ParseIP("192.168.10.10")},
	})
	ok, reason := chain.Decide("https://evil.example.net/x", resolve)
	if ok || reason != "host-not-public" {
		t.Fatalf("expected host-not-public via dns, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainDNSRebinding(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	calls := 0
	resolve := func(host string) ([]net.IP, error) {
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("203.0.113.9")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	if ok, reason := chain.Decide("https://cdn.example.net/a", resolve); !ok {
		t.Fatalf("first resolution: %s", reason)
	}
	if ok, reason := chain.Decide("https://cdn.example.net/b", resolve); ok || reason != "dns-rebinding" {
		t.Fatalf("expected dns-rebinding, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainResolveFailure(t *testing.T) {
	chain, _ := newRedirectChain("https://piston-data.mojang.com/f", defaultRedirectLimits())
	resolve := stubResolver(map[string][]net.IP{})
	ok, reason := chain.Decide("https://nope.example.net/x", resolve)
	if ok || reason != "dns-resolve-failed" {
		t.Fatalf("expected dns-resolve-failed, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainCrossHostPolicy(t *testing.T) {
	lim := RedirectLimits{MaxHops: 5, AllowCrossHost: false}
	chain, _ := newRedirectChain("https://cdn.minecraft.net/f", lim)
	ok, reason := chain.Decide("https://evil.example.net/x", nil)
	if ok || reason != "cross-host-denied" {
		t.Fatalf("expected cross-host-denied, got ok=%v reason=%s", ok, reason)
	}
	// 同注册域后缀允许。
	chain2, _ := newRedirectChain("https://minecraft.net/f", lim)
	ok, reason = chain2.Decide("https://libraries.minecraft.net/x", nil)
	if !ok {
		t.Fatalf("expected same registrable allow, got %s", reason)
	}
}

func TestRedirectChainMaxHops(t *testing.T) {
	lim := RedirectLimits{MaxHops: 2}
	chain, _ := newRedirectChain("https://cdn.example.net/a", lim)
	if ok, reason := chain.Decide("https://cdn.example.net/b", nil); !ok {
		t.Fatalf("hop 1: %s", reason)
	}
	ok, reason := chain.Decide("https://cdn.example.net/c", nil)
	if ok || reason != "too-many-hops" {
		t.Fatalf("expected too-many-hops, got ok=%v reason=%s", ok, reason)
	}
}

func TestRedirectChainProtocolRelative(t *testing.T) {
	chain, _ := newRedirectChain("https://cdn.example.net/a/b", defaultRedirectLimits())
	ok, reason := chain.Decide("//cdn2.example.net/c", nil)
	if !ok {
		t.Fatalf("protocol-relative should resolve, got %s", reason)
	}
	last := chain.Links()[1]
	if last != "https://cdn2.example.net/c" {
		t.Fatalf("protocol-relative mismatch: %s", last)
	}
}

func TestRedirectChainEmptyLocation(t *testing.T) {
	chain, _ := newRedirectChain("https://cdn.example.net/a", defaultRedirectLimits())
	for _, loc := range []string{"", "   "} {
		ok, reason := chain.Decide(loc, nil)
		if ok || reason != "empty-location" {
			t.Fatalf("expected empty-location, got ok=%v reason=%s", ok, reason)
		}
	}
}

func TestIPSetEqual(t *testing.T) {
	a := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}
	b := []net.IP{net.ParseIP("2.2.2.2"), net.ParseIP("1.1.1.1")}
	c := []net.IP{net.ParseIP("1.1.1.1")}
	d := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("3.3.3.3")}
	if !ipSetEqual(a, b) {
		t.Fatal("expected equal unordered sets")
	}
	if ipSetEqual(a, c) || ipSetEqual(a, d) {
		t.Fatal("expected unequal sets")
	}
}
