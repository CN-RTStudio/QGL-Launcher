package main

import (
	"strings"
)

// reportMin 资源上界（默认策略）。
const (
	reportMinMaxBytes      = 8 << 20 // 序列化总预算 8MB
	reportMinMaxArrayItems = 500     // 单数组最多保留条数
	reportMinMaxDepth      = 8       // 嵌套深度上限
	reportMinMaxFieldLen   = 400     // 单字段值最大字节数
)

// reportAllowedFields 是允许进入上报的字段名白名单（键统一小写，匹配时大小写不敏感）。
// 白名单之外的字段（如环境变量、绝对路径、内部 ID）一律丢弃。
var reportAllowedFields = map[string]bool{
	"version":       true,
	"generatedat":   true,
	"baselineat":    true,
	"baselinedirs":  true,
	"total":         true,
	"consistent":    true,
	"skipped":       true,
	"limithit":      true,
	"hasrisks":      true,
	"added":         true,
	"missing":       true,
	"tampered":      true,
	"addedcount":    true,
	"missingcount":  true,
	"tamperedcount": true,
	"eventid":       true,
	"category":      true,
	"severity":      true,
	"action":        true,
	"source":        true,
	"detail":        true,
	"host":          true,
	"count":         true,
	"kind":          true,
	"dir":           true,
	"relpath":       true,
	"name":          true,
	"ok":            true,
}

// ReportPolicy 是一次最小化的策略参数（可注入以便测试边界）。
type ReportPolicy struct {
	MaxBytes      int
	MaxArrayItems int
	MaxDepth      int
	MaxFieldLen   int
	AllowField    func(string) bool
}

// defaultReportPolicy 返回默认上报策略（全字段上界取常量）。
func defaultReportPolicy() ReportPolicy {
	return ReportPolicy{
		MaxBytes:      reportMinMaxBytes,
		MaxArrayItems: reportMinMaxArrayItems,
		MaxDepth:      reportMinMaxDepth,
		MaxFieldLen:   reportMinMaxFieldLen,
		AllowField: func(field string) bool {
			return reportAllowedFields[strings.ToLower(field)]
		},
	}
}

func ScrubTelemetryValue(s string) string {
	if s == "" {
		return ""
	}
	// 先整段剥终端转义序列（motdguard 内核）：报告值里出现 ESC/CSI/OSC 本身就是
	// 注入痕迹，剥序列而不是只删 ESC，避免残留 “[31m” 这类可见垃圾。
	s = stripTerminalSequences(s)
	out := make([]byte, 0, len(s))
	// 折叠控制字符（保留可打印与常见标点）；CRLF 连续时只留一个空格。
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' {
			if !prevSpace {
				out = append(out, ' ')
				prevSpace = true
			}
			continue
		}
		if c < 0x20 || c == 0x7f {
			continue
		}
		prevSpace = c == ' '
		out = append(out, c)
	}
	s = string(out)

	// URL userinfo 与 query token：逐个“http(s)://”段扫描。
	s = scrubURLTokens(s)
	// 长十六进制串掩码（至少 40 位，防 token/指纹泄出）。
	s = maskLongHex(s)
	// 绝对路径剥除（Windows 与 Unix 两种前缀，URL 段已做保护区）。
	s = scrubLocalPaths(s)
	return s
}

func scrubURLTokens(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	lower := strings.ToLower(s)
	pos := 0
	for {
		// 通用 scheme 检测：找 "://"，再向左回溯协议名起点（http/https/wss 等）。
		idx := strings.Index(lower[pos:], "://")
		if idx < 0 {
			b.WriteString(s[pos:])
			break
		}
		colon := pos + idx
		start := colon
		for start > 0 && isSchemeChar(lower[start-1]) {
			start--
		}
		if start == colon || !isAlpha(lower[start]) {
			b.WriteString(s[pos : colon+3])
			pos = colon + 3
			continue
		}
		b.WriteString(s[pos:start])
		// 找到协议段起点：剥 userinfo（:// 前的 user:pass@）。
		rest := s[start:]
		if at := strings.Index(rest, "@"); at >= 0 && at < 64 {
			// 形如 scheme://user:pass@ 或 scheme://user@
			if schemeEnd := strings.Index(rest, "://"); schemeEnd >= 0 && schemeEnd < at {
				rest = rest[:schemeEnd+3] + "[redacted]" + rest[at+1:]
			}
		}
		b.WriteString(rest)
		break
	}
	s = b.String()
	// 查询参数中的常见凭据键：长键优先（防止 "token" 先匹配到 "access_token"
	// 的子串，把整个键名替换掉），逐一处理。
	for _, key := range []string{"access_token", "api_key", "password", "apikey", "secret", "sign", "token", "key"} {
		s = scrubQueryKey(s, key)
	}
	return s
}
