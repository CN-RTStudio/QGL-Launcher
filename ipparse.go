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

// canonicalHostName 把主机名归一化成比较用的形态：去空白、去掉表示绝对域名的
// 尾随点、转小写。DNS 对 "LOCALHOST" / "localhost." 与 "localhost" 解析结果一致，
// 字符串态判定必须先做这一步，否则同一个目标会因写法不同走出不同结论。
func canonicalHostName(host string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(host)), ".")
}

// isLoopbackHostName 判定主机名是否是“永远指向本机”的保留名字。这些名字在任何
// 解析器下都落到回环地址，字符串态就不可能解析成公网 IP，必须在拨号之前就按回环
// 处理，不能指望 DNS 层兜底（"localhost." / "LOCALHOST" 这类写法在历史上的
// 字符串判定里会被当成普通域名放行）。
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

// parseDestIP 判断 host 是不是 IP 字面量并还原成规范 net.IP。
// 域名（含 localhost、单标签主机名）返回 ok=false。识别顺序：
//  1. 去掉 IPv6 作用域（%eth0）与空白；
//  2. net.ParseIP 覆盖全部规范 IPv6 / IPv4；
//  3. IPv4-mapped IPv6 内嵌非规范 IPv4；
//  4. 非规范点分 IPv4；
//  5. 单个十进制 / 十六进制 / 八进制整数。
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

// isNonPublicIP 是全启动器唯一的“目标 IP 是否禁止主动连出 / 禁止交给系统浏览器”
// 判定内核。出向拨号守卫 safeDialContext（含 DNS rebinding 兜底）、外部浏览器打开、
// 短链 / 重定向 / 代理链等全部复用这一份，避免历史上两套手写分段表严格度不一致
// （拨号守卫的多播只拦 224.0.0/24，漏掉 224/4 其余多播与 240/4 保留段）。
//
// 只拦“连上后可能落到本机 / 内网身份，或在本地链路产生广播 / 多播副作用”的地址：
// 回环、未指定、0.0.0.0/8 本网络、RFC1918、CGNAT 100.64/10、链路本地 169.254/16、
// 整个 224.0.0.0/4（多播，含 SSDP 239.255.255.250）与 240.0.0.0/4（保留，含
// 255.255.255.255 有限广播），以及 IPv6 回环 / 未指定 / 多播 / 链路本地 / 唯一本地
// fc00::/7。
//
// 刻意不拦 RFC5737 文档段（192.0.2/24、198.51.100/24、203.0.113/24）、RFC2544 基准段
// 198.18/15、已废弃的 6to4 中继 192.88.99/24 与 IPv6 文档段 2001:db8::/32：它们全局
// 不可路由，连不通任何主机、不构成内网跳板，且本仓库测试有意用其作公网占位。
// nil 视为不可信（true）。
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
