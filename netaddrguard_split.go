package main

import (
	"strconv"
	"strings"
)

// NormalizeIPv4 严格校验点分十进制 IPv4：必须恰好四段，每段 1-3 位纯数字、
// 取值 0-255。显式拒绝前导零（"01" / "00"），因为不同下游对前导零有八进制 /
// 十进制两种解释，属于歧义面；返回规范的 "a.b.c.d"。
func NormalizeIPv4(s string) (string, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	out := make([]string, 0, 4)
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return "", false
		}
		// 拒绝前导零歧义：除单独的 "0" 外，任何以 0 开头的多位数都不接受。
		if len(p) > 1 && p[0] == '0' {
			return "", false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return "", false
			}
		}
		out = append(out, strconv.Itoa(n))
	}
	return strings.Join(out, "."), true
}

// validateHostnameShape 校验 DNS 主机名（非 IP 字面量）：总长、标签长、允许字符
// （字母数字与连字符）、标签不得以连字符开头 / 结尾。末尾允许单个根点但内部归一。
func validateHostnameShape(host string) bool {
	if host == "" || len(host) > maxHostnameLen {
		return false
	}
	h := host
	if strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
		if h == "" {
			return false
		}
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if label == "" || len(label) > maxHostnameLabel {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
				continue
			default:
				return false
			}
		}
	}
	return true
}
