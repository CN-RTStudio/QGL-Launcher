package main

import (
	"net"
	"net/url"
	"strings"
)

const maxRedirectHops = 3

var shortenerHosts = map[string]bool{
	"bit.ly":      true,
	"t.co":        true,
	"goo.gl":      true,
	"tinyurl.com": true,
	"is.gd":       true,
	"s.id":        true,
	"t.cn":        true,
	"dwz.cn":      true,
	"url.cn":      true,
	"u.nu":        true,
	"rb.gy":       true,
	"cutt.ly":     true,
	"shorte.st":   true,
	"suo.im":      true,
	"tiny.cc":     true,
	"shorturl.at": true,
	"v.gd":        true,
}

type HostResolver func(host string) ([]net.IP, error)

func knownShortenerHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimPrefix(h, "www.")
	h = strings.TrimRight(h, ".")
	if h == "" {
		return false
	}
	return shortenerHosts[h]
}
func isShortLinkURL(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	return knownShortenerHost(u.Hostname())
}
