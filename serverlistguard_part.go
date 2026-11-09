package main

import (
	"errors"
	"strings"
)

type ServerEntry struct {
	Host   string
	Port   int
	Name   string
	Kind   ServerKind
	Source string // 原始行（净化后），供审计
}

// ParseServerAddress 解析 "host[:port]"；port 缺省为 25565。
// 拒绝：空 host、控制字符、空格、引号、分号、逗号、路径分隔、URL 方案前缀、
// 端口越界或非数字。
func ParseServerAddress(raw string, lim ServerListLimits) (ServerEntry, error) {
	d := lim.withDefaults()
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ServerEntry{}, errors.New("server address is empty")
	}
	if len([]rune(trimmed)) > d.MaxLineRunes {
		return ServerEntry{}, errors.New("server address too long")
	}
	if serverTextHasFormatRune(raw) {
		return ServerEntry{}, errors.New("server address contains control characters")
	}
	if strings.ContainsAny(trimmed, " \t\"';,<>") {
		return ServerEntry{}, errors.New("server address contains forbidden characters")
	}
	// 拒绝 URL 方案前缀与路径形状。
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"http://", "https://", "mc://", "minecraft://"} {
		if strings.HasPrefix(lower, prefix) {
			return ServerEntry{}, errors.New("server address must not include url scheme")
		}
	}
	if strings.ContainsAny(trimmed, `/\`) {
		return ServerEntry{}, errors.New("server address must not contain path separators")
	}

	hostPart := trimmed
	port := 25565
	bracketed := false
	if strings.HasPrefix(trimmed, "[") {
		bracketed = true
		end := strings.IndexByte(trimmed, ']')
		if end < 0 {
			return ServerEntry{}, errors.New("server address has unterminated ipv6 bracket")
		}
		hostPart = trimmed[1:end]
		suffix := trimmed[end+1:]
		if suffix != "" {
			if suffix == ":" {
				return ServerEntry{}, errors.New("server address has empty port")
			}
			if !strings.HasPrefix(suffix, ":") {
				return ServerEntry{}, errors.New("server address has invalid port")
			}
			portValue, ok := parseServerPort(suffix[1:], d.MaxPort)
			if !ok {
				return ServerEntry{}, errors.New("server address has invalid port")
			}
			port = portValue
		}
	} else if strings.Count(trimmed, ":") == 1 {
		i := strings.IndexByte(trimmed, ':')
		hostPart = trimmed[:i]
		portRaw := trimmed[i+1:]
		if portRaw == "" {
			return ServerEntry{}, errors.New("server address has empty port")
		}
		portValue, ok := parseServerPort(portRaw, d.MaxPort)
		if !ok {
			return ServerEntry{}, errors.New("server address has invalid port")
		}
		port = portValue
	}
	if hostPart == "" {
		return ServerEntry{}, errors.New("server address has empty host")
	}
	if len([]rune(hostPart)) > d.MaxHostRunes {
		return ServerEntry{}, errors.New("server host too long")
	}
	// host 内不允许再次出现冒号（IPv6 带端口形态已由 LastIndexByte 拆开；
	// 裸 IPv6 无端口时冒号是合法字符，这里按无端口处理）。
	if strings.Contains(hostPart, " ") {
		return ServerEntry{}, errors.New("server host contains whitespace")
	}
	if !bracketed && strings.Contains(hostPart, ":") {
		if _, ok := parseDestIP(hostPart); !ok {
			return ServerEntry{}, errors.New("server host has stray colon")
		}
	}

	return ServerEntry{
		Host:   hostPart,
		Port:   port,
		Kind:   classifyServerHost(hostPart),
		Source: trimmed,
	}, nil
}

// classifyServerHost 判断 host 的分类：回环 / 私有 / IP / 域名。
//
// IP 判定统一走 ipparse.go 的 parseDestIP + isNonPublicIP：既识别规范四段，也识别
// 2130706433、0x7f000001、017700000001、127.1 等 inet_aton 整数 / 进制 / 短格式混淆，
// 避免私网服务器被这些写法标成普通公网 IP（历史上本文件的 isLoopbackHost /
// isPrivateIPv4 只认严格四段、且 IPv6 用 "fc"/"fd" 字符串前缀粗判，口径偏松且重复）。
