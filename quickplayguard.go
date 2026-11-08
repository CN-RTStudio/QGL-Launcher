package main

// quickplayguard.go —— Quick Play 直连参数校验。
//
// MC 1.20+ 支持从启动器直接 `--quickPlaySingleplayer <world>` /
// `--quickPlayMultiplayer <host:port>` / `--quickPlayRealms <id>`。这些字符串由用户
// 或外部链接（deeplink/快捷方式）传入，直接拼到 JVM 参数上有注入风险。
// 这里只做“这个值能不能安全塞进命令行参数”的判定，不解析真实联机。

import (
	"fmt"
	"net"
	"strings"
)

// QuickPlayTarget 是一次 Quick Play 目标。
type QuickPlayTarget struct {
	Mode string // singleplayer / multiplayer / realms
	Arg  string
}

func isSafeQuickPlayPort(port string) bool {
	if len(port) == 0 || len(port) > 5 {
		return false
	}
	if port[0] == '0' && len(port) > 1 {
		return false
	}
	n := 0
	for i := 0; i < len(port); i++ {
		c := port[i]
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 65535
}

func isSafeQuickPlayHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	labelLen := 0
	labelFirst := byte(0)
	labelLast := byte(0)
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c == '.' {
			if labelLen == 0 || labelLen > 63 || labelFirst == '-' || labelLast == '-' {
				return false
			}
			labelLen = 0
			labelFirst = 0
			labelLast = 0
			continue
		}
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
		if labelLen == 0 {
			labelFirst = c
		}
		labelLast = c
		labelLen++
	}
	return labelLen > 0 && labelLen <= 63 && labelFirst != '-' && labelLast != '-'
}

func isSafeRealmsID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	c := id[0]
	firstOK := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	if !firstOK {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

// ValidateQuickPlayArg 按模式校验 Quick Play 参数。
func ValidateQuickPlayArg(mode, arg string) error {
	a := strings.TrimSpace(arg)
	if a == "" {
		return fmt.Errorf("empty quickplay arg")
	}
	if strings.ContainsAny(a, "\r\n") {
		return fmt.Errorf("newline in quickplay arg")
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "singleplayer":
		// 存档名只允许安全字符，禁止路径穿越。
		if strings.ContainsAny(a, `/\:*?"<>|`) || strings.Contains(a, "..") {
			return fmt.Errorf("unsafe world name: %q", a)
		}
	case "multiplayer":
		host, port, ok := splitQueueAuthority(a)
		if !ok {
			return fmt.Errorf("bad mp authority: %q", a)
		}
		// 允许只给主机，默认 25565。
		if port == "" {
			port = "25565"
		}
		host = strings.Trim(host, "[]")
		if !isSafeQuickPlayHost(host) {
			return fmt.Errorf("bad mp host: %q", a)
		}
		if !isSafeQuickPlayPort(port) {
			return fmt.Errorf("bad port: %q", port)
		}
	case "realms":
		if !isSafeRealmsID(a) {
			return fmt.Errorf("bad realms id: %q", a)
		}
	default:
		return fmt.Errorf("unknown quickplay mode: %q", mode)
	}
	return nil
}

// AllowQuickplay 便捷布尔入口。
func AllowQuickplay(mode, arg string) bool {
	return ValidateQuickPlayArg(mode, arg) == nil
}
