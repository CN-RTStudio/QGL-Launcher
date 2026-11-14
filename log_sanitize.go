package main

import (
	"regexp"
)

// 日志脱敏：把 Minecraft / Java / 微软 / Yggdrasil 交互日志里常见的敏感信息打码，
// 避免 MC access token / 会话 id / 密钥 / 邮箱 / 内网 IP / Bearer 凭证 / JWT
// 通过 Wails 事件送到前端、或经 writeLog 明文落进 qgl_install.log / 启动日志。
//
// 设计要点：
//   - 脱敏是“宁可错杀”的最后一道闸：误伤普通文本可以接受，漏放凭证不行；
//   - 规则按特异性从高到低排列（Bearer、JWT 先于通用 key=value）；
//   - RE2 不支持环视，统一用“捕获前缀 + 整体替换”实现，不依赖回溯。
var (
	// reBearer 匹配 Authorization: Bearer xxxx 这类 HTTP 认证头（冒号或等号分隔，
	// 允许中间有空白/引号）。
	reBearer = regexp.MustCompile("(?i)(authorization\\s*[:=]\\s*\"?)(?:bearer|token|basic|digest|negotiate|ntlm)\\s+[A-Za-z0-9_\\-\\.~+/]+=*")

	// reJWT 匹配三段式 JWT（header 以 eyJ 开头），即使不带 key 名也打码。
	reJWT = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}`)

	// reSecretKV 匹配 key=value / "key": "value" 形式的敏感字段。
	// 第 1 组是键名，第 2 组是键名与值之间的分隔符（兼容键名后的闭合引号、
	// 冒号/等号、空白与值前的引号），值取到引号、空白或 JSON 结构符之前，
	// 至少 6 个字符，避免误伤短词。
	reSecretKV = regexp.MustCompile("(?i)\\b(access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|session[_-]?token|client[_-]?token|client[_-]?secret|api[_-]?key|app[_-]?secret|xbox[_-]?token|xsts[_-]?token|private[_-]?key|passphrase|credential|session[_-]?id|password|passwd|session|secret|token|pwd|cookie|set[_-]?cookie)(\"?\\s*[:=]\\s*\"?)[^\"\\s&,;}]{6,}")

	reCLIFlag = regexp.MustCompile("(?i)(--(?:accessToken|clientToken|refreshToken|sessionId|apiKey|clientSecret|authToken|password|passwd|pwd|secret|token|key)\\s*[= ]\\s*)([^\\s\"']+)")

	reShortSecretKV = regexp.MustCompile("(?i)\\b(password|passwd|pwd|secret|token|api[_-]?key|cookie)(\"?\\s*[:=]\\s*\"?)((?-i:[^\"\\s&,;}]*[0-9A-Z_\\-+/=])[^\"\\s&,;}]{0,4})([\\s\"',;}]|$)")

	rePrivateIP    = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}|198\.1[89]\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b`)
	reEmail        = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reUUID         = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	reAnsiEscape   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]`)
	reControlChars = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)
	reBidiControls = regexp.MustCompile("[\u202a-\u202e\u2066-\u2069]")
	reZeroWidth    = regexp.MustCompile("[\u200b-\u200f\u2060\ufeff]")
	rePrivateIPv6  = regexp.MustCompile(`(?i)\b(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f])[0-9a-f:]{2,}`)
	reLoopbackIPv6 = regexp.MustCompile(`(^|[^0-9a-fA-F:])(::1)([^0-9a-fA-F:]|$)`)
	reMappedIPv6   = regexp.MustCompile(`(?i)\b::ffff:(?:\d{1,3}\.){3}\d{1,3}\b`)
	reUserPath     = regexp.MustCompile(`(?i)(^|[^\w\\/-])(?:[A-Z]:\\Users\\|/home/|/Users/)[^\\/\s"'<>]+`)
	reUrlUserInfo  = regexp.MustCompile(`(?i)(\b[0-9a-z+.\-]+://)([^/@\s"'<>]+@)`)
	reBareBearer   = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9_\-.~+/]{8,}=*`)
)

// sanitizeLogLine 对单行日志做脱敏。命中即替换为占位符，保证凭证不落盘、不外发。
func sanitizeLogLine(line string) string {
	// Bearer 认证头整体替换，但保留 "Authorization:" 前缀便于排查是哪一类头。
	line = reAnsiEscape.ReplaceAllString(line, "")
	line = reControlChars.ReplaceAllString(line, "")
	line = reBidiControls.ReplaceAllString(line, "")
	line = reZeroWidth.ReplaceAllString(line, "")
	line = reBearer.ReplaceAllString(line, "${1}[REDACTED]")
	line = reBareBearer.ReplaceAllString(line, `[REDACTED]`)
	// 裸 JWT 直接抹掉（放在 key=value 之前，避免被通用规则切成半段）。
	line = reJWT.ReplaceAllString(line, "[JWT]")
	// key=value / "key": "value" 形式保留键名与分隔符，只抹值。
	line = reSecretKV.ReplaceAllString(line, "${1}${2}[REDACTED]")
	line = reShortSecretKV.ReplaceAllString(line, "${1}${2}[REDACTED]${4}")
	// 启动命令行用空格分隔（java ... --accessToken xxx），不在 key=value 规则里。
	line = reCLIFlag.ReplaceAllString(line, "${1}[REDACTED]")
	line = reUrlUserInfo.ReplaceAllString(line, "${1}[REDACTED]@")
	line = reEmail.ReplaceAllString(line, `[EMAIL]`)
	line = reUUID.ReplaceAllString(line, `[UUID]`)
	line = rePrivateIP.ReplaceAllString(line, `[LAN-IP]`)
	line = rePrivateIPv6.ReplaceAllString(line, `[LAN-IP]`)
	line = reLoopbackIPv6.ReplaceAllString(line, "${1}[LAN-IP]${3}")
	line = reMappedIPv6.ReplaceAllString(line, `[LAN-IP]`)
	line = reUserPath.ReplaceAllString(line, "${1}[USER-HOME]")
	return line
}
