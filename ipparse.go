package main

// ipparse.go 负责“出向目标主机”的 IP 字面量识别。
//
// 背景：umfs.go 里的 SSRF 守卫原本只用 net.ParseIP 判断主机是不是内网地址。
// net.ParseIP 只接受规范写法（"127.0.0.1"、"::1"、"::ffff:127.0.0.1"），
// 但操作系统 socket 与不少 HTTP 客户端在真正建连时接受一大串“等价但非规范”的
// IP 写法。攻击者可以用这些写法让字符串态检查放行、建连时却连到内网：
//
//	十进制整数      http://2130706433/        -> 127.0.0.1
//	十六进制整数    http://0x7f000001/        -> 127.0.0.1
//	八进制整数      http://017700000001/      -> 127.0.0.1
//	十六进制分段    http://0x7f.0.0.1/        -> 127.0.0.1
//	八进制分段      http://0177.0.0.1/        -> 127.0.0.1
//	压缩点分        http://0x7f.1/           -> 127.0.0.1
//	映射 IPv6       http://[::ffff:7f00:1]/  -> 127.0.0.1
//	映射 IPv6 内嵌  http://[::ffff:2130706433]/（net.ParseIP 解析失败）
//
// 这里在“发请求前的字符串态”和“建连前的 Dial 态”都用同一个更宽的解析器兜底：
// 只要主机能被识别成任意形态的 IP 字面量，就按真实 32 位地址做内网判定；
// 普通域名仍返回 ok=false，交给 DNS 与 safeDialContext 的 rebinding 防护。

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
