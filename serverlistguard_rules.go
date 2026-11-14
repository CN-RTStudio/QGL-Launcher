package main

import (
	"strings"
)

func classifyServerHost(host string) ServerKind {
	if isLoopbackHostName(host) {
		return ServerKindLoopback
	}
	if ip, ok := parseDestIP(host); ok {
		if ip.IsLoopback() {
			return ServerKindLoopback
		}
		// 非回环的非公网地址（RFC1918、链路本地、CGNAT、0/8、多播 / 保留、
		// fc00::/7、fe80::/10 等）对服务器列表而言都归入“私有 / 内网目标”。
		if isNonPublicIP(ip) {
			return ServerKindPrivate
		}
		return ServerKindIP
	}
	// parseDestIP 解析不出来时，保留历史“含冒号即按 IP 字面量”的宽松口径，
	// 不把畸形 IPv6 误标成普通域名。
	if isIPLiteralHost(host) {
		return ServerKindIP
	}
	return ServerKindHostname
}
func SanitizeServerName(name string, lim ServerListLimits) string {
	d := lim.withDefaults()
	clean := name
	// 统一走 strings.Map 剥控制字符：不依赖 hasControlCharStr 预闸门（它只扫
	// 原始字节 ≤0x1F，会漏掉 C1 控制区 U+0080-U+009F 的 UTF-8 编码）。
	clean = strings.Map(func(r rune) rune {
		if serverFormatRune(r) {
			return -1
		}
		return r
	}, clean)
	clean = strings.TrimSpace(clean)
	if len([]rune(clean)) > d.MaxNameRunes {
		clean = string([]rune(clean)[:d.MaxNameRunes])
	}
	return clean
}
