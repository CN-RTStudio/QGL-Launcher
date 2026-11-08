package main

// launchererrormessagefilter.go —— 错误消息二次净化。
//
// 启动器把 JVM/下载/校验的错误直接弹给用户时，里面经常夹着 access token、
// 文件系统绝对路径里的用户名、代理密码。这里再跑一道纯函数，把这些东西
// 替成占位符，避免"截图发群求助"时顺手把凭据泄出去。

import (
	"regexp"
	"strings"
)

var (
	errTokPattern = regexp.MustCompile(`(?i)(access_?token|session|bearer|authorization|secret|password)["'=\s]+[A-Za-z0-9._\-]{8,}`)
	errPathUser   = regexp.MustCompile(`(?i)([A-Za-z]:\\Users\\)[^\\/:"<>|?*]+`)
	errBearer     = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._\-]{16,}`)
)

// SanitizeErrorForUser 把一段原始错误文本处理成可以安全展示给用户/贴进 issue 的版本。
func SanitizeErrorForUser(msg string) string {
	if msg == "" {
		return ""
	}
	out := errBearer.ReplaceAllString(msg, "Bearer <redacted>")
	out = errTokPattern.ReplaceAllString(out, "$1=<redacted>")
	out = errPathUser.ReplaceAllString(out, "$1<User>")
	return strings.TrimSpace(out)
}

// ShouldShowToUser 决定这段错误是否适合直接弹给普通用户。
// 命中内部堆栈、SQL、路径穿越特征时返回 false，应该只写日志。
func ShouldShowToUser(msg string) bool {
	s := strings.ToLower(msg)
	if strings.Contains(s, "goroutine ") && strings.Contains(s, ".go:") {
		return false
	}
	if strings.Contains(s, "..") && strings.Contains(s, "\\") {
		return false
	}
	return true
}
