package main

import (
	"net"
	"strings"
)

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
