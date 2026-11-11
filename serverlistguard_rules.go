package main

import (
	"strconv"
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

func serverTextHasFormatRune(s string) bool {
	for _, r := range s {
		if serverFormatRune(r) {
			return true
		}
	}
	return false
}
func (l *ServerListLimits) withDefaults() ServerListLimits {
	if l == nil {
		l = &ServerListLimits{}
	}
	out := *l
	if out.MaxHostRunes <= 0 {
		out.MaxHostRunes = 255
	}
	if out.MaxNameRunes <= 0 {
		out.MaxNameRunes = 96
	}
	if out.MaxPort <= 0 {
		out.MaxPort = 65535
	}
	if out.MaxLines <= 0 {
		out.MaxLines = 512
	}
	if out.MaxLineRunes <= 0 {
		out.MaxLineRunes = 4096
	}
	return out
}

type ServerKind int

const (
	ServerKindHostname ServerKind = iota // 普通域名
	ServerKindIP                         // IPv4/IPv6 字面量
	ServerKindLoopback                   // 127.0.0.0/8、::1
	ServerKindPrivate                    // RFC1918 / 链路本地
)

func (k ServerKind) String() string {
	switch k {
	case ServerKindIP:
		return "ip"
	case ServerKindLoopback:
		return "loopback"
	case ServerKindPrivate:
		return "private"
	default:
		return "hostname"
	}
}
