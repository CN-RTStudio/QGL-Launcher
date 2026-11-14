package main

import (
	"strings"
)

func looksIPv4(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	first := host
	if i := strings.IndexByte(first, '.'); i >= 0 {
		first = first[:i]
	}
	if first == "" {
		return false
	}
	for i := 0; i < len(first); i++ {
		if first[i] < '0' || first[i] > '9' {
			return false
		}
	}
	return true
}

// ParseHostPort 把 "host:port"（IPv6 用 "[v6]:port"）解析为 HostPort。
// 只做结构解析与端口数值化；主机语义（IP / 主机名）的严格校验在 validateHost 内。
