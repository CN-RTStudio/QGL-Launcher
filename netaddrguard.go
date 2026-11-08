package main

// netaddrguard.go —— 主机:端口（host:port）目标地址的严格解析 / 校验内核。
//
// 威胁模型：
//   OpenQGL 有多处把“主机 + 端口”拼成字符串后继续使用：
//     - 局域网联机连接码解析（ParseConnectionCode）还原出 IPv4:端口；
//     - 外部认证服务器 / 皮肤站地址；
//     - 将来“直连服务器地址”等前端入参。
//   这些地址字符串是多源外部输入。若只按字符串拼接而不校验结构，畸形值可能在下游
//   被二次解释：夹带 scheme（http://）、userinfo（a@b）、路径 / 查询片段、空白与控制
//   字符、越界端口、非法 IPv4 段、未加方括号的裸 IPv6 等，都会让“一个地址”携带额外
//   语义，造成 SSRF 目标漂移、命令行 / 配置注入或不可预期的连接行为。
//
// 本内核只做纯解析，不发起任何网络请求，便于穷举单测：
//   - NormalizeIPv4：严格四段点分十进制，每段 0-255，拒绝前导零歧义 / 空白 / 越界；
//   - ParseHostPort：把 host:port 拆成结构化 {Host, Port, IsIPv6}，拒绝额外语义；
//   - ValidateHostPort：解析 + 主机形态 + 端口范围的一站式裁决。
// 连接码内核（connectioncodeguard）在还原地址后调用本内核做最终形态校验，保证
// “解析出来的东西一定是一个干净的 host:port”。

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
	addrRejectNone       = ""
	addrRejectEmpty      = "empty-address"      // 空地址
	addrRejectLength     = "address-too-long"   // 超长
	addrRejectControl    = "control-character"  // 含空白 / 控制字符
	addrRejectScheme     = "embedded-scheme"    // 夹带 ://
	addrRejectUserInfo   = "embedded-userinfo"  // 夹带 @
	addrRejectPath       = "embedded-path"      // 夹带 / ? #
	addrRejectNoPort     = "missing-port"       // 无端口
	addrRejectBadPort    = "bad-port"           // 端口非数字 / 越界
	addrRejectIPv4Shape  = "bad-ipv4"           // 形似 IPv4 但段非法
	addrRejectIPv6Shape  = "bad-ipv6"           // 方括号内不是合法 IPv6
	addrRejectHostname   = "bad-hostname"       // 主机名形态非法
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
