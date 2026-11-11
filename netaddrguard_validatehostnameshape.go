package main

import (
	"fmt"
	"strings"
)

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

// validateHost 对解析出的主机做语义校验：IPv6 已在解析阶段保证是字面量；
// 形似 IPv4 的走严格四段路径；其余按 DNS 主机名规则。
func (hp *HostPort) validateHost() string {
	if hp.IsIPv6 {
		return addrRejectNone
	}
	if looksIPv4(hp.Host) {
		if _, ok := NormalizeIPv4(hp.Host); !ok {
			return addrRejectIPv4Shape
		}
		return addrRejectNone
	}
	if !validateHostnameShape(hp.Host) {
		return addrRejectHostname
	}
	return addrRejectNone
}

// String 还原为规范的 host:port（IPv6 自动补方括号）。
func (hp *HostPort) String() string {
	if hp.IsIPv6 {
		return fmt.Sprintf("[%s]:%d", hp.Host, hp.Port)
	}
	return fmt.Sprintf("%s:%d", hp.Host, hp.Port)
}
