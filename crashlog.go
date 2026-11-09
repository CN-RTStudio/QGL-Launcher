package main

// crashlog.go —— 崩溃转储 / 日志文本的敏感信息脱敏内核。
//
// 威胁模型：崩溃转储（hs_err_pid*.log、dumpCrashContext 收集的尾部输出）会
// 原样记录绝对路径、用户名目录、机器名、命令行。这些文件可能被用户贴到
// 论坛 / 工单 / 粘贴板，或由错误上报通道外发；不脱敏会把启动器安装位置、
// Windows 用户名等暴露给第三方。
//
// 做法：对外发/落盘的崩溃文本统一过 redactCrashText：
//   - 本机用户目录（C:\Users\<name>）→ <redacted-user>；
//   - QGL 根目录 / .minecraft 目录 → <redacted-home>；
//   - 形如 eyJ... 的 JWT / accessToken 长令牌 → <redacted-token>；
//   - 高熵长串（连续 32+ 位十六进制 / base64 特征）→ <redacted-hex>。
// 纯函数、大小写不敏感目录匹配，保留其余内容原样，便于定位崩溃点。

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

// userDirVariants 生成用户名目录的常见写法（正/反斜杠、引号包裹、前加
// Windows 盘符与 Users 段）。
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

// replaceDirCI 大小写不敏感地替换目录路径及其带尾分隔符变体。
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
