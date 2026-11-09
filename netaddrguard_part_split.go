package main

import (
	"fmt"
)

// validateHost 对解析出的主机做语义校验：IPv6 已在解析阶段保证是字面量；
// 形似 IPv4 的走严格四段路径；其余按 DNS 主机名规则。
func (hp *HostPort) validateHost() string {
	if hp.IsIPv6 {
		return addrRejectNone
	}
	if looksIPv4(hp.Host) {
		if _, ok := NormalizeIPv4(hp.Host); !ok {
			return addrRejectIPv4Shape
		}
		return addrRejectNone
	}
	if !validateHostnameShape(hp.Host) {
		return addrRejectHostname
	}
	return addrRejectNone
}

// String 还原为规范的 host:port（IPv6 自动补方括号）。
func (hp *HostPort) String() string {
	if hp.IsIPv6 {
		return fmt.Sprintf("[%s]:%d", hp.Host, hp.Port)
	}
	return fmt.Sprintf("%s:%d", hp.Host, hp.Port)
}

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
