package main

import ()

// ValidateHostPort 是一站式裁决：合法返回规范化地址串，否则返回拒绝原因码。
func ValidateHostPort(addr string) (string, string) {
	hp, why := ParseHostPort(addr)
	if why != addrRejectNone {
		return "", why
	}
	if why := hp.validateHost(); why != addrRejectNone {
		return "", why
	}
	if !hp.IsIPv6 && looksIPv4(hp.Host) {
		norm, _ := NormalizeIPv4(hp.Host)
		hp.Host = norm
	}
	return hp.String(), addrRejectNone
}

// looksIPv4 粗略判断是否“长得像 IPv4”（含点且首段全数字），用于区分该走 IPv4
// 严格路径还是主机名路径，避免把 1.2.3.坏 当主机名放行。
