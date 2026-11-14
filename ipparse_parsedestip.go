package main

import (
	"net"
	"strings"
)

func parseDestIP(host string) (net.IP, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, false
	}
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return nil, false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, true
	}
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed != host {
		if ip := net.ParseIP(trimmed); ip != nil {
			return ip, true
		}
	}
	if strings.Contains(trimmed, ":") {
		return parseMappedIPv6(trimmed)
	}
	if strings.Contains(trimmed, ".") {
		return parseObfuscatedIPv4(trimmed)
	}
	if v, ok := parseIPPiece(trimmed); ok && v >= 0 && uint64(v) < uint64(1)<<32 {
		return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)), true
	}
	return nil, false
}

// isZeroNetworkIPv4 报告是否属于 0.0.0.0/8（“本网络”源地址段）。
// 该段在多数系统上建连会被映射到本机，绝不该被启动器主动连出。
func isZeroNetworkIPv4(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 0
}

func isNonPublicIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6（::ffff:a.b.c.d）会被 To4 还原，统一按内嵌 IPv4 判定。
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case isZeroNetworkIPv4(ip): // 0.0.0.0/8
			return true
		case ip4[0] == 10: // 10.0.0.0/8
			return true
		case ip4[0] == 127: // 127.0.0.0/8 loopback
			return true
		case ip4[0] == 100 && ip4[1]&0xc0 == 64: // 100.64.0.0/10 CGNAT
			return true
		case ip4[0] == 169 && ip4[1] == 254: // 169.254.0.0/16 link-local
			return true
		case ip4[0] == 172 && ip4[1]&0xf0 == 16: // 172.16.0.0/12
			return true
		case ip4[0] == 192 && ip4[1] == 168: // 192.168.0.0/16
			return true
		case ip4[0] >= 224: // 224.0.0.0/4 多播 + 240.0.0.0/4 保留 + 有限广播
			return true
		}
		return false
	}
	if v4, ok := embeddedTransitionIPv4(ip); ok {
		return isNonPublicIP(v4)
	}
	// 原生 IPv6：回环 / 未指定 / 多播 / 链路本地（单播+多播）/ 唯一本地 fc00::/7。
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}
