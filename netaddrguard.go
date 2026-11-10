package main

import (
	"fmt"
	"net"
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

// ValidateHostPort 是一站式裁决：合法返回规范化地址串，否则返回拒绝原因码。
func ValidateHostPort(addr string) (string, string) {
	hp, why := ParseHostPort(addr)
	if why != addrRejectNone {
		return "", why
	}
	if why := hp.validateHost(); why != addrRejectNone {
		return "", why
	}
	if !hp.IsIPv6 && looksIPv4(hp.Host) {
		norm, _ := NormalizeIPv4(hp.Host)
		hp.Host = norm
	}
	return hp.String(), addrRejectNone
}

// looksIPv4 粗略判断是否“长得像 IPv4”（含点且首段全数字），用于区分该走 IPv4
// 严格路径还是主机名路径，避免把 1.2.3.坏 当主机名放行。
func looksIPv4(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	first := host
	if i := strings.IndexByte(first, '.'); i >= 0 {
		first = first[:i]
	}
	if first == "" {
		return false
	}
	for i := 0; i < len(first); i++ {
		if first[i] < '0' || first[i] > '9' {
			return false
		}
	}
	return true
}

// ParseHostPort 把 "host:port"（IPv6 用 "[v6]:port"）解析为 HostPort。
// 只做结构解析与端口数值化；主机语义（IP / 主机名）的严格校验在 validateHost 内。
func ParseHostPort(addr string) (*HostPort, string) {
	if addr == "" {
		return nil, addrRejectEmpty
	}
	if len(addr) > maxHostPortLen {
		return nil, addrRejectLength
	}
	if hasSpaceOrControl(addr) {
		return nil, addrRejectControl
	}
	if strings.Contains(addr, "://") {
		return nil, addrRejectScheme
	}
	// userinfo（a@b）在目标地址里没有正当含义，直接拒。
	if strings.Contains(addr, "@") {
		return nil, addrRejectUserInfo
	}
	// 路径 / 查询 / 片段会给“一个地址”附加额外语义，拒绝。
	if strings.ContainsAny(addr, "/?#") {
		return nil, addrRejectPath
	}

	host := addr
	var portStr string
	isIPv6 := false

	if strings.HasPrefix(addr, "[") {
		// 字面量 IPv6 必须用方括号包裹，端口在右括号之后。
		closeBracket := strings.IndexByte(addr, ']')
		if closeBracket < 0 {
			return nil, addrRejectIPv6Shape
		}
		lit := addr[1:closeBracket]
		rest := addr[closeBracket+1:]
		if lit == "" || net.ParseIP(lit) == nil || net.ParseIP(lit).To4() != nil {
			// 括号内为空、非法，或其实是 IPv4（应走点分路径），都判畸形。
			return nil, addrRejectIPv6Shape
		}
		if rest == "" {
			return nil, addrRejectNoPort
		}
		if rest[0] != ':' || rest[1:] == "" {
			return nil, addrRejectBadPort
		}
		portStr = rest[1:]
		host = lit
		isIPv6 = true
	} else {
		// 裸 IPv6（含多个冒号且无方括号）不接受：没有方括号无法与 host:port 消歧。
		colon := strings.LastIndexByte(addr, ':')
		if colon < 0 {
			return nil, addrRejectNoPort
		}
		host = addr[:colon]
		portStr = addr[colon+1:]
		if strings.Count(addr, ":") > 1 {
			return nil, addrRejectIPv6Shape
		}
	}

	for i := 0; i < len(portStr); i++ {
		if portStr[i] < '0' || portStr[i] > '9' {
			return nil, addrRejectBadPort
		}
	}
	if len(portStr) > 1 && portStr[0] == '0' {
		return nil, addrRejectBadPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || portStr == "" {
		return nil, addrRejectBadPort
	}
	if port < 1 || port > 65535 {
		return nil, addrRejectBadPort
	}
	if host == "" {
		return nil, addrRejectEmpty
	}

	return &HostPort{Host: host, Port: port, IsIPv6: isIPv6}, addrRejectNone
}
