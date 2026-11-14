package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func sameRegistrable(host, base string) bool {
	if base == "" {
		return false
	}
	return host == base || strings.HasSuffix(host, "."+base)
}

// ipSetEqual 比较两个 IP 集合是否一致（顺序无关）。
func ipSetEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, ip := range a {
		m[ip.String()]++
	}
	for _, ip := range b {
		k := ip.String()
		if m[k] == 0 {
			return false
		}
		m[k]--
	}
	return true
}

func newRedirectChain(entry string, lim RedirectLimits) (*redirectChain, error) {
	if lim.MaxHops <= 0 {
		lim = defaultRedirectLimits()
	}
	u, err := url.Parse(strings.TrimSpace(entry))
	if err != nil {
		return nil, fmt.Errorf("redirect-chain: bad entry url: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	c := &redirectChain{
		seen:      map[string]bool{},
		schemes:   map[string]bool{},
		hostIPs:   map[string][]net.IP{},
		firstHost: host,
		limits:    lim,
	}
	c.schemes[strings.ToLower(u.Scheme)] = true
	c.seen[normalizeRedirectURL(u)] = true
	c.links = append(c.links, u.String())
	return c, nil
}
