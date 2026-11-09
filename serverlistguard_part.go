package main

import (
	"errors"
	"strconv"
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

// SanitizeServerName 净化服务器名称：剥控制字符、限长；空名称回退空串。
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

// ParseServerListText 解析多行服务器列表（每行 "名称地址" 或 "名称 host:port"，
// 兼容 "名称|host:port"）。返回净化后的条目数组；单行失败跳过并记录错误。
func ParseServerListText(text string, lim ServerListLimits) ([]ServerEntry, []string) {
	d := lim.withDefaults()
	if hasControlCharStr(text) {
		text = strings.Map(func(r rune) rune {
			if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
				return -1
			}
			return r
		}, text)
	}
	lines := strings.Split(text, "\n")
	if len(lines) > d.MaxLines {
		lines = lines[:d.MaxLines]
	}
	entries := make([]ServerEntry, 0, len(lines))
	var errs []string
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// 尝试切分名称与地址：最后一个空白或竖线。
		name, addr := splitServerLine(line)
		if addr == "" {
			addr = line
			name = ""
		}
		entry, err := ParseServerAddress(addr, d)
		if err != nil {
			errs = append(errs, "line rejected: "+err.Error())
			continue
		}
		entry.Name = SanitizeServerName(name, d)
		entries = append(entries, entry)
	}
	return entries, errs
}

// splitServerLine 从 "名称 host:port" / "名称|host:port" 拆出名称与地址；
// 拆不出地址时返回 ("", 原行)。
func splitServerLine(line string) (name, addr string) {
	if i := strings.LastIndexByte(line, '|'); i >= 0 {
		return line[:i], line[i+1:]
	}
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		return strings.Join(fields[:len(fields)-1], " "), fields[len(fields)-1]
	}
	return "", line
}

// SummarizeServerEntries 输出一行审计摘要。
func SummarizeServerEntries(entries []ServerEntry, errs []string) string {
	var sb strings.Builder
	sb.WriteString("serverlist parsed entries=")
	sb.WriteString(strconv.Itoa(len(entries)))
	if len(errs) > 0 {
		sb.WriteString(" errors=")
		sb.WriteString(strconv.Itoa(len(errs)))
	}
	return sb.String()
}
