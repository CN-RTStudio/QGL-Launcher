package main

import (
	"net"
	"strings"
)

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
