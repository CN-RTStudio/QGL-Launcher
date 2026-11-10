package main

import (
	"net"
	"strconv"
	"strings"
)

// parseIPPiece 解析 IP 的一个数值分段，支持十进制 / 0x 十六进制 / 0o 或前导 0
// 八进制。返回该分段的数值、是否为“数字字面量”（含歧义的前导 0 写法也算）。
//
// 前导 0 在不同实现里可能被当成八进制或十进制：为了不漏，先按八进制解析，
// 失败（含 8/9 数字）再回退十进制。只要它整体是数字，调用方就应当把它当作
// IP 字面量而不是域名处理。
func parseIPPiece(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseInt(s[2:], 16, 64)
		return v, err == nil
	}
	if strings.HasPrefix(s, "0o") || strings.HasPrefix(s, "0O") {
		v, err := strconv.ParseInt(s[2:], 8, 64)
		return v, err == nil
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	if len(s) > 1 && s[0] == '0' {
		if v, err := strconv.ParseInt(s, 8, 64); err == nil {
			return v, true
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err == nil
}

func canonicalHostName(host string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
}
func isLoopbackHostName(host string) bool {
	name := canonicalHostName(host)
	if name == "" {
		return false
	}
	if name == "localhost" || name == "ip6-localhost" || name == "ip6-loopback" {
		return true
	}
	return strings.HasSuffix(name, ".localhost")
}

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

func embeddedTransitionIPv4(ip net.IP) (net.IP, bool) {
	if len(ip) != net.IPv6len {
		return nil, false
	}
	nat64 := ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b
	if nat64 {
		for i := 4; i < 12; i++ {
			if ip[i] != 0 {
				nat64 = false
				break
			}
		}
		if nat64 {
			return net.IPv4(ip[12], ip[13], ip[14], ip[15]), true
		}
	}
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]), true
	}
	compatible := true
	for i := 0; i < 12; i++ {
		if ip[i] != 0 {
			compatible = false
			break
		}
	}
	if compatible && (ip[12] != 0 || ip[13] != 0 || ip[14] != 0 || ip[15] != 0) {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]), true
	}
	teredo := ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00
	if teredo {
		raw := net.IPv4(ip[12], ip[13], ip[14], ip[15])
		v4 := raw.To4()
		return net.IPv4(v4[0]^0xff, v4[1]^0xff, v4[2]^0xff, v4[3]^0xff), true
	}
	return nil, false
}

func inetAtonLike(parts []string) (net.IP, bool) {
	n := len(parts)
	if n < 1 || n > 4 {
		return nil, false
	}
	var addr uint32
	for i, p := range parts {
		v, ok := parseIPPiece(p)
		if !ok || v < 0 {
			return nil, false
		}
		last := i == n-1
		width := uint(8)
		if last {
			width = uint((5 - n) * 8)
		}
		if uint64(v) >= uint64(1)<<width {
			return nil, false
		}
		shift := uint(0)
		if !last {
			// 非末段总是按其段序号落在固定字节位：a 在最高字节(24)，依次 16/8；
			// 段数 n 只改变“末段”吞掉的低位数，不影响前面段的位置。
			shift = uint(3-i) * 8
		}
		addr |= uint32(v) << shift
	}
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)), true
}

func parseObfuscatedIPv4(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	return inetAtonLike(parts)
}

// parseMappedIPv6 处理 net.ParseIP 不接受、但建连时仍可能被解释成 IPv4 的
// IPv4-mapped / IPv4-compatible IPv6 字面量，例如 "::ffff:2130706433"、
// "::ffff:0x7f.1"、"::2130706433"。返回内嵌的 IPv4 地址。
func parseMappedIPv6(host string) (net.IP, bool) {
	lower := strings.ToLower(host)
	rest := ""
	switch {
	case strings.HasPrefix(lower, "::ffff:"):
		rest = host[len("::ffff:"):]
	case strings.HasPrefix(lower, "::"):
		rest = host[len("::"):]
	default:
		return nil, false
	}
	if rest == "" || strings.Contains(rest, ":") {
		return nil, false
	}
	if ip, ok := parseObfuscatedIPv4(rest); ok {
		return ip, true
	}
	return nil, false
}
