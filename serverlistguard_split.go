package main

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
