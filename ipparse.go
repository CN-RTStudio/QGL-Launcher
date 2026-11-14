package main

import (
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
