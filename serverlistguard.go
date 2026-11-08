package main

// serverlistguard.go —— Minecraft 服务器地址/服务器列表导入校验内核。
//
// 背景：
//   OpenQGL 支持导入/收藏服务器地址（servers 列表），地址随后会被用于连接
//   请求与 UI 展示。攻击面集中在：
//     1) 地址注入：恶意服务器列表把 host 写成带空格、引号、分号、换行、
//        URL 方案（http://）、路径（/..）的串——若拼进连接命令或当作参数
//        传递，会造成命令注入 / 参数污染；若直接展示，会撑破 UI 布局；
//     2) 端口伪装：默认 MC 端口 25565；攻击者可把地址写成 "127.0.0.1:1"
//        （内网拨号）或 ":0"，诱导用户连到非预期端口；
//     3) IP 直连：LAN 服务器场景合法，但公网导入应提示——本模块给每行
//        地址打分类（hostname / ip / loopback / private），让上层决定是否
//        警告，而不是一刀切拒绝；
//     4) 名称字段：服务器名称是可展示文本，必须剥控制字符并限长，防止
//        ANSI 转义注入终端日志。
//   输出为净化后的规范行 + 分类，供上层持久化与展示。

import (
	"errors"
	"strconv"
	"strings"
)

// ServerListLimits 限定服务器地址与名称的输入边界。
type ServerListLimits struct {
	MaxHostRunes int
	MaxNameRunes int
	MaxPort      int
	MaxLines     int
	MaxLineRunes int
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

// ServerKind 描述服务器地址的网络分类。
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

// ServerEntry 是一条净化后的服务器记录。
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
	if hasControlCharStr(trimmed) {
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
	if i := strings.LastIndexByte(trimmed, ':'); i >= 0 {
		hostPart = trimmed[:i]
		portRaw := trimmed[i+1:]
		if portRaw == "" {
			return ServerEntry{}, errors.New("server address has empty port")
		}
		p, err := strconv.Atoi(portRaw)
		if err != nil || p < 1 || p > d.MaxPort {
			return ServerEntry{}, errors.New("server address has invalid port")
		}
		port = p
	}
	hostPart = strings.TrimSuffix(strings.TrimPrefix(hostPart, "["), "]")
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
		// 删 ASCII 控制区 (0x00-0x1F)、DEL (0x7F) 以及 C1 控制区 (0x80-0x9F)。
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
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
