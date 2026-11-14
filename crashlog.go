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

func userDirVariants(username string) []string {
	variants := []string{
		`Users\` + username,
		`Users/` + username,
		`\Users\` + username,
		`/Users/` + username,
		`"C:\Users\` + username + `"`,
		`C:\Users\` + username,
		`c:\users\` + strings.ToLower(username),
	}
	seen := make(map[string]bool, len(variants))
	var out []string
	for _, v := range variants {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func replaceDirCI(text, dir, placeholder string) string {
	dir = strings.TrimRight(strings.TrimSpace(dir), `\/`)
	if dir == "" {
		return text
	}
	variants := []string{dir, strings.ToLower(dir), strings.ToUpper(dir)}
	for _, v := range variants {
		// 正斜杠变体与反斜杠变体都要覆盖。
		bs := strings.ReplaceAll(v, `/`, `\`)
		fs := strings.ReplaceAll(v, `\`, `/`)
		text = strings.ReplaceAll(text, bs, placeholder)
		text = strings.ReplaceAll(text, fs, placeholder)
		// 尾分隔符变体（目录后跟 \ 或 /）。
		text = strings.ReplaceAll(text, bs+`\`, placeholder+`\`)
		text = strings.ReplaceAll(text, fs+`/`, placeholder+`/`)
	}
	return text
}

// crashTextPreview 生成崩溃文本的脱敏预览（用于审计事件 detail，限长）。
func crashTextPreview(text string, maxLen int) string {
	t := strings.TrimSpace(text)
	if len(t) > maxLen {
		t = t[:maxLen] + "..."
	}
	return t
}

// currentUsername 返回当前登录用户名（供脱敏用；未登录返回空）。
func (a *App) currentUsername() string {
	if u, err := a.GetCurrentUser(); err == nil {
		return u.Username
	}
	return ""
}
