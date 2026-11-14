package main

import (
	"strings"
)

const (
	// maxYggProfileNameLen Minecraft 角色名上限（历史上为 16）。
	maxYggProfileNameLen = 16
	// minYggProfileNameLen Minecraft 角色名下限。
	minYggProfileNameLen = 1
	// maxYggTokenLen 外置 accessToken / clientToken 的长度上限，挡住超长串灌入加密存储与命令行。
	maxYggTokenLen = 4096
	// maxYggServerNameLen 皮肤站自报名称（meta.serverName）长度上限。
	maxYggServerNameLen = 128
)
const (
	ypOK        = ""
	ypNameEmpty = "ygg-name-empty"
	ypNameLen   = "ygg-name-length"
	ypNameChar  = "ygg-name-charset"
	ypUUIDBad   = "ygg-uuid-bad"
	ypTokenBad  = "ygg-token-bad"
)

func validateYggProfileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ypNameEmpty
	}
	if len(name) < minYggProfileNameLen || len(name) > maxYggProfileNameLen {
		return ypNameLen
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z') &&
			!(c >= 'A' && c <= 'Z') &&
			!(c >= '0' && c <= '9') &&
			c != '_' {
			return ypNameChar
		}
	}
	return ypOK
}

// canonicalYggProfileUUID 校验并归一角色 UUID。
// 接受 32 位十六进制（无连字符）或 8-4-4-4-12 带连字符两种形式，
// 统一返回 32 位小写十六进制；非法返回 ok=false。
func canonicalYggProfileUUID(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 5 ||
			len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
			len(parts[3]) != 4 || len(parts[4]) != 12 {
			return "", false
		}
		s = strings.Join(parts, "")
	}
	if len(s) != 32 {
		return "", false
	}
	for _, c := range s {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return "", false
		}
	}
	return strings.ToLower(s), true
}
