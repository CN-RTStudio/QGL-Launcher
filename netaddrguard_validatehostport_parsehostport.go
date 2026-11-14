package main

import (
	"net"
	"strconv"
	"strings"
)

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
