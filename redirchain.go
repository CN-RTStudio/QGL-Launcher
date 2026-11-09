package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type RedirectLimits struct {
	MaxHops         int
	AllowDropToHTTP bool
	AllowCrossHost  bool
}

func defaultRedirectLimits() RedirectLimits {
	return RedirectLimits{
		MaxHops:         5,
		AllowDropToHTTP: false,
		AllowCrossHost:  true,
	}
}

type redirectChain struct {
	links     []string
	seen      map[string]bool
	schemes   map[string]bool
	hostIPs   map[string][]net.IP
	firstHost string
	limits    RedirectLimits
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
