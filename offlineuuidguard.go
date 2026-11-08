package main

// offlineuuidguard.go —— 离线模式玩家 UUID 派生与校验。
//
// 离线服务器（online-mode=false）的玩家 UUID 是固定算法：
//
//	UUID.nameUUIDFromBytes(("OfflinePlayer:" + name).getBytes(UTF_8))
//
// 也就是 MD5 后按 RFC 4122 置 version=3 / variant 位。这是 Minecraft 协议约定，
// 不能换成 UMFS。这里把派生和“是不是合法离线 UUID”收敛成纯函数，避免启动器
// 自己手搓字节序，也防止把脏名字/空白名直接喂进去。

import (
	"crypto/md5"
	"fmt"
	"strings"
)

// OfflineUUID 按离线服务器约定派生玩家 UUID（大写连字符形式）。
// name 会先做基本清洗；非法名返回错误。
func OfflineUUID(name string) (string, error) {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return "", fmt.Errorf("empty player name")
	}
	if strings.ContainsAny(clean, "\r\n\t") {
		return "", fmt.Errorf("control chars in player name")
	}
	sum := md5.Sum([]byte("OfflinePlayer:" + clean))
	b := sum[:]
	// RFC 4122 version 3：高 4 位置 0011。
	b[6] = (b[6] & 0x0f) | 0x30
	// variant 10xx。
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// IsOfflineUUID 校验一个字符串是不是合法的 UUID v3（离线 UUID 形态）。
// 只做形态与版本/变体位校验，不重算 MD5（因为我们不知道原始名字）。
func IsOfflineUUID(s string) bool {
	// 接受带/不带连字符两种形态，统一成 32 hex。
	hex := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(hex) != 32 {
		return false
	}
	for i := 0; i < 32; i++ {
		c := hex[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !ok {
			return false
		}
	}
	version := hex[12]
	// 离线 UUID 一定是 v3。
	if version != '3' {
		return false
	}
	variant := hex[16]
	// 高两位应为 10：8/9/a/b。
	switch variant {
	case '8', '9', 'a', 'b', 'A', 'B':
		return true
	}
	return false
}
