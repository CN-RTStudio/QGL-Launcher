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
	reBearer   = regexp.MustCompile("(?i)(authorization\\s*[:=]\\s*\"?)(?:bearer|token)\\s+[A-Za-z0-9_\\-\\.~+/]+=*")

	// reJWT 匹配三段式 JWT（header 以 eyJ 开头），即使不带 key 名也打码。
	reJWT      = regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}`)

	// reSecretKV 匹配 key=value / "key": "value" 形式的敏感字段。
	// 第 1 组是键名，第 2 组是键名与值之间的分隔符（兼容键名后的闭合引号、
	// 冒号/等号、空白与值前的引号），值取到引号、空白或 JSON 结构符之前，
	// 至少 6 个字符，避免误伤短词。
	reSecretKV = regexp.MustCompile("(?i)\\b(access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|api[_-]?key|app[_-]?secret|xbox[_-]?token|xsts[_-]?token|session[_-]?id|password|passwd|session|secret|token|pwd)(\"?\\s*[:=]\\s*\"?)[^\"\\s&,;}]{6,}")

	rePrivateIP = regexp.MustCompile(`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
	reEmail     = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reUUID      = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
)

// sanitizeLogLine 对单行日志做脱敏。命中即替换为占位符，保证凭证不落盘、不外发。
func sanitizeLogLine(line string) string {
	// Bearer 认证头整体替换，但保留 "Authorization:" 前缀便于排查是哪一类头。
	line = reBearer.ReplaceAllString(line, "${1}[REDACTED]")
	// 裸 JWT 直接抹掉（放在 key=value 之前，避免被通用规则切成半段）。
	line = reJWT.ReplaceAllString(line, "[JWT]")
	// key=value / "key": "value" 形式保留键名与分隔符，只抹值。
	line = reSecretKV.ReplaceAllString(line, "${1}${2}[REDACTED]")
	line = reEmail.ReplaceAllString(line, `[EMAIL]`)
	line = reUUID.ReplaceAllString(line, `[UUID]`)
	line = rePrivateIP.ReplaceAllString(line, `[LAN-IP]`)
	return line
}
