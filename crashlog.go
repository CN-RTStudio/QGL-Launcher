package main

import (
	"regexp"
	"strings"
)

// redactedUser / redactedHome / redactedToken / redactedHex 是替换占位符。
const (
	redactedUser  = "<redacted-user>"
	redactedHome  = "<redacted-home>"
	redactedToken = "<redacted-token>"
	redactedHex   = "<redacted-hex>"
)

// reJWTish 匹配 eyJ 开头的 JWT 风格长令牌（JWT 三段、每段 ≥4 字符）。
var reJWTish = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]{4,}`)

// reLongHex 匹配连续 32+ 位十六进制（SHA256/SHA1 等哈希或随机串）。
var reLongHex = regexp.MustCompile(`[0-9a-fA-F]{32,}`)

// redactCrashText 对崩溃文本脱敏。qglDir / mcDir / username 为空时跳过对应
// 目录替换；路径统一转小写比较（Windows 大小写不敏感）。
func redactCrashText(text, qglDir, mcDir, username string) string {
	if text == "" {
		return text
	}
	// 1) 用户目录替换（含带引号 / 反斜杠变体）。
	if username != "" {
		for _, variant := range userDirVariants(username) {
			text = strings.ReplaceAll(text, variant, redactedUser)
		}
	}
	// 2) QGL / 游戏目录替换。
	if qglDir != "" {
		text = replaceDirCI(text, qglDir, redactedHome)
	}
	if mcDir != "" {
		text = replaceDirCI(text, mcDir, redactedHome)
	}
	// 3) JWT / 长令牌替换。
	text = reJWTish.ReplaceAllString(text, redactedToken)
	// 4) 高熵十六进制长串替换（避免把随机 token 误判为路径而泄漏）。
	text = reLongHex.ReplaceAllString(text, redactedHex)
	return text
}
