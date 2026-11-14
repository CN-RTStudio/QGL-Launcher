package main

import (
	"strconv"
	"strings"
)

const (
	// maxHostPortLen 限制单条目标地址总长度（DNS 名 253 + 方括号 IPv6 45 + 端口 6 + 余量）。
	maxHostPortLen = 512
	// maxHostnameLen 是 DNS 主机名总长度上限（RFC 1035：253，含点）。
	maxHostnameLen = 253
	// maxHostnameLabel 是单个 DNS 标签长度上限（RFC 1035：63）。
	maxHostnameLabel = 63
)

// HostPort 是解析后的结构化目标地址。
type HostPort struct {
	Host   string // 已去空白 / 去方括号的主机部分
	Port   int    // 数值化端口
	IsIPv6 bool   // 主机是否为字面量 IPv6（输入时必须带 []）
}

// 地址裁决拒绝原因码（纯常量，便于单测断言与审计归类）。
const (
	addrRejectNone      = ""
	addrRejectEmpty     = "empty-address"     // 空地址
	addrRejectLength    = "address-too-long"  // 超长
	addrRejectControl   = "control-character" // 含空白 / 控制字符
	addrRejectScheme    = "embedded-scheme"   // 夹带 ://
	addrRejectUserInfo  = "embedded-userinfo" // 夹带 @
	addrRejectPath      = "embedded-path"     // 夹带 / ? #
	addrRejectNoPort    = "missing-port"      // 无端口
	addrRejectBadPort   = "bad-port"          // 端口非数字 / 越界
	addrRejectIPv4Shape = "bad-ipv4"          // 形似 IPv4 但段非法
	addrRejectIPv6Shape = "bad-ipv6"          // 方括号内不是合法 IPv6
	addrRejectHostname  = "bad-hostname"      // 主机名形态非法
)

// hasSpaceOrControl 判断是否含空白或 ASCII 控制字符（地址里绝不允许出现）。
func hasSpaceOrControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

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
