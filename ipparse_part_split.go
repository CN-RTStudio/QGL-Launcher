package main

import "net"

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
