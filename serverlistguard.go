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

import "strconv"

// ServerListLimits 限定服务器地址与名称的输入边界。
type ServerListLimits struct {
	MaxHostRunes int
	MaxNameRunes int
	MaxPort      int
	MaxLines     int
	MaxLineRunes int
}

func serverFormatRune(r rune) bool {
	if r < 0x20 || r == 0x7f {
		return true
	}
	if r >= 0x80 && r <= 0x9f {
		return true
	}
	if r >= 0x202a && r <= 0x202e {
		return true
	}
	if r >= 0x2066 && r <= 0x2069 {
		return true
	}
	switch r {
	case 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2028, 0x2029, 0xfeff:
		return true
	}
	return false
}

func parseServerPort(raw string, max int) (int, bool) {
	if raw == "" {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 || v > max {
		return 0, false
	}
	return v, true
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
