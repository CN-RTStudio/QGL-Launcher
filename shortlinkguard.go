package main

import (
	"fmt"
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

func preflightShortLink(rawURL string, hops int, resolve HostResolver) (string, error) {
	if hops < 0 || hops > maxRedirectHops {
		return "", fmt.Errorf("重定向跳数超过上限 %d", maxRedirectHops)
	}
	norm, err := normalizeScheme(rawURL)
	if err != nil {
		return "", err
	}
	if !isShortLinkURL(norm) {
		// 非短链的普通 https 公网 URL 不额外折腾（私网拦截在 netaddrguard /
		// 下载器既有防线里处理），这里只保证协议与 userinfo 合规。
		return norm, nil
	}
	if v := guardRedirectTarget(norm, resolve); v.Blocked {
		return "", fmt.Errorf("短链目标预检拒绝: %s", v.Reason)
	}
	return norm, nil
}

// preflightRedirectHop 校验重定向链上的一跳（跟随 Location 前调用）：
// 目标必须是 https 公网且不指向私网；hops 为该跳序号（从 1 开始）。
