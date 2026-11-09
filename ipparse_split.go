package main

import (
	"net"
	"strings"
)

// inetAtonLike 按 inet_aton 位宽规则把 1~4 段数字拼成 IPv4。段数位宽：
//
//	a            整段 32 位
//	a.b          a 高 8 位，b 低 24 位
//	a.b.c        a、b 各 8 位，c 低 16 位
//	a.b.c.d      每段 8 位
//
// 任一分段不是数字、为负或超出其位宽，都返回 ok=false，避免把含数字的域名
// 误判成地址。
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

// parseObfuscatedIPv4 还原非规范点分 / 整数形态的 IPv4 字面量。
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
