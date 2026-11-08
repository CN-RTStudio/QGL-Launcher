package main

// reportmin.go —— 遥测 / 报告“最小化”内核。
//
// 威胁模型：
//   安全审计事件、异常报告、未来可能接出的诊断上报里，detail 字段经常带本机
//   绝对路径（C:\Users\…\mods\xxx.jar）、令牌 / 长串密钥、带 userinfo 的 URL。
//   这类数据一旦随报告被分享给他人、或未来接入任何遥测通道，就会泄露：
//     - 本机目录结构 / 用户名（社工面）；
//     - 访问令牌（如果日志里混入 Authorization 或 query token）；
//     - 敏感文件的真实位置（帮助定向攻击）。
//
//   本内核提供三层最小化：
//     - 字段白名单：只有登记过的字段名允许进入上报；未登记字段整体丢弃；
//     - 值去敏：本机路径剥成 <本地路径> 或仅保留文件名；URL userinfo / query
//       token 剥除；40+ 位十六进制长串掩码；换行折叠（防日志注入换行）；
//     - 结构预算：数组条数、嵌套深度、单字段长度、总字节都有硬上界，递归
//       遍历时超出即截断，保证“最小化后的负载”体积有界、可穷举测试。
//
//   纯函数、不发起网络请求；落审计日志与未来上报前都必须过一遍。

import (
	"encoding/json"
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

// ScrubTelemetryValue 对单条文本做值级去敏（不改变长度语义外的结构）：
//  1. 折叠 CR/LF（防日志注入：攻击者把 detail 写成多行伪造审计条目）；
//  2. 剥 URL userinfo 与常见 query token（?token=、?key=、?sign= 等）；
//  3. 40 位以上十六进制长串（疑似密钥 / 指纹）掩码；
//  4. 本机绝对路径（Windows 盘符 / Unix 根路径）剥成占位符或文件名。
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

// scrubURLTokens 剥 URL 里的 userinfo 与查询凭据参数。
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

// scrubQueryKey 剥掉单个查询参数键的取值（只保留键名占位，不输出原值；吞掉后继 '&'）。
func scrubQueryKey(s, key string) string {
	needle := key + "="
	lower := strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	pos := 0
	for {
		idx := strings.Index(lower[pos:], needle)
		if idx < 0 {
			b.WriteString(s[pos:])
			break
		}
		start := pos + idx
		// 词边界：键名必须是独立词，不能是更长标识符的一部分。
		// 否则处理完 "access_token" 后，占位串里的 "token=" 会被 "token" 键
		// 二次匹配，把后续内容一并吞掉。
		if start > 0 && isWordChar(s[start-1]) {
			b.WriteString(s[pos : start+1])
			pos = start + 1
			continue
		}
		b.WriteString(s[pos:start])
		end := start + len(needle)
		for end < len(s) && s[end] != '&' && s[end] != ' ' && s[end] != '#' {
			end++
		}
		// 只输出键名 + 占位符，绝不把取值原文写回（防部分值泄露）。
		b.WriteString(s[start:start+len(needle)] + "[redacted]")
		if end < len(s) && s[end] == '&' {
			end++ // 吞掉后继分隔符，不留空参数
		}
		pos = end
	}
	return b.String()
}

// maskLongHex 把 40 位以上的连续十六进制串掩码成 <hex40+>。
func maskLongHex(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		c := s[i]
		if isHexDigit(c) {
			j := i
			for j < len(s) && isHexDigit(s[j]) {
				j++
			}
			if j-i >= 40 {
				b.WriteString("<hex" + strings.Repeat("x", 4) + "+>")
			} else {
				b.WriteString(s[i:j])
			}
			i = j
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// isHexDigit 判断字节是否是十六进制数字。
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isWordChar 判断字节是否是标识符词字符（字母 / 数字 / 下划线），
// 用于给凭据键名做词边界判定。
func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '_'
}

// scrubLocalPaths 把本机绝对路径替换成占位符（或仅保留文件名）。
func scrubLocalPaths(s string) string {
	// Windows：X:\… 与 \\server\share\…；Unix：/…（至少两段）。
	var b strings.Builder
	b.Grow(len(s))
	// URL 段保护区：http(s)://… 直到空白/引号的整段不再进路径判定，
	// 避免 “https://host/path” 的 “//” 被误当成 Unix 绝对路径剥除。
	protected := markURLSpans(s)
	i := 0
	for i < len(s) {
		if protected[i] {
			// URL 段原样通过（userinfo/query 已由 scrubURLTokens 处理过）。
			b.WriteByte(s[i])
			i++
			continue
		}
		if isWinDriveStart(s, i) {
			end := i
			for end < len(s) && s[end] != ' ' && s[end] != '"' && s[end] != '\t' {
				end++
			}
			// 保留最后一个路径段作为文件名线索（≤40 字节），其余掩码。
			seg := s[i:end]
			name := lastPathSegment(seg)
			if name == "" {
				name = "<local-path>"
			}
			b.WriteString("<本地路径:" + name + ">")
			i = end
			continue
		}
		if s[i] == '/' && i+1 < len(s) && s[i+1] != ' ' {
			// Unix 绝对路径：/a/b 形态（单段根目录不掩码，防误伤表达式）。
			end := i
			for end < len(s) && s[end] != ' ' && s[end] != '"' && s[end] != '\t' {
				end++
			}
			seg := s[i:end]
			slashes := strings.Count(seg, "/")
			if slashes >= 2 {
				name := lastPathSegment(seg)
				if name == "" {
					name = "<local-path>"
				}
				b.WriteString("<本地路径:" + name + ">")
				i = end
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// isWinDriveStart 判断位置是否是一个 Windows 盘符路径或 UNC 路径起点。
func isWinDriveStart(s string, i int) bool {
	if i+1 < len(s) && (s[i+1] == ':') && isDriveLetter(s[i]) {
		if i+2 < len(s) && (s[i+2] == '\\' || s[i+2] == '/') {
			return true
		}
	}
	// UNC：\\host\share\…
	return i+1 < len(s) && s[i] == '\\' && s[i+1] == '\\'
}

// isDriveLetter 判断字节是否是一个盘符字母。
func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isSchemeChar 判断字节是否属于协议名字符集（字母数字 . + -）。
func isSchemeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-'
}

// isAlpha 判断字节是否是英文字母。
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// markURLSpans 标记字符串里任意 scheme:// 段的索引区间为保护区（返回与输入等长的
// bool 数组；非 URL 段为 false）。协议名 + "://" 之后的字符直到空白 / 引号 /
// 制表符 / 查询串 / fragment 都属于 URL 段——路径剥除必须跳过它们；查询串与
// fragment 不保护，交给路径剥除处理（防本地路径随参数值进遥测）。
func markURLSpans(s string) []bool {
	protected := make([]bool, len(s))
	i := 0
	for i < len(s) {
		rest := s[i:]
		idx := strings.Index(rest, "://")
		if idx < 0 {
			break
		}
		colon := i + idx
		// 从 "://" 向左回溯协议名起点（字母数字 . + - 都是协议名一部分）。
		start := colon
		for start > 0 && isSchemeChar(s[start-1]) {
			start--
		}
		// 协议名必须非空且以字母开头（"123://" 不视为 URL）。
		if start == colon || !isAlpha(s[start]) {
			i = colon + 3
			continue
		}
		body := colon + 3
		end := body
		// 保护区只覆盖 scheme://host/path（到查询串 / fragment 为止）。
		for end < len(s) && s[end] != ' ' && s[end] != '"' && s[end] != '\t' &&
			s[end] != '?' && s[end] != '#' {
			end++
		}
		// 从协议名起点（含 “://”）到查询串 / fragment 之前整段标记，
		// 防止 “//” 被路径剥除误伤；查询串本身不保护（见上）。
		for j := start; j < end; j++ {
			protected[j] = true
		}
		i = end
	}
	return protected
}

// lastPathSegment 取路径最后一个分隔符后的段（限 40 字节）。
func lastPathSegment(p string) string {
	idx := strings.LastIndexAny(p, `/\`)
	seg := p
	if idx >= 0 && idx+1 < len(p) {
		seg = p[idx+1:]
	}
	if len(seg) > 40 {
		seg = seg[:40]
	}
	return seg
}

// MinimizeMap 对扁平字段表做白名单 + 长度 + 预算最小化；返回保留字段数与丢弃数。
func MinimizeMap(in map[string]string) (map[string]string, int) {
	pol := defaultReportPolicy()
	out := make(map[string]string, len(in))
	var dropped int
	for k, v := range in {
		if !pol.AllowField(k) {
			dropped++
			continue
		}
		v = ScrubTelemetryValue(v)
		if len(v) > pol.MaxFieldLen {
			v = v[:pol.MaxFieldLen-3] + "..."
		}
		out[k] = v
	}
	return out, dropped
}

// minimizeAny 递归最小化任意 JSON 值；返回（处理后值, 是否被截断）。
func minimizeAny(v interface{}, depth int, pol ReportPolicy) (interface{}, bool) {
	if depth > pol.MaxDepth {
		return "<深度超限>", true
	}
	switch t := v.(type) {
	case nil, bool, float64, string:
		return t, false
	case []interface{}:
		var out []interface{}
		trunc := false
		for i, item := range t {
			if i >= pol.MaxArrayItems {
				trunc = true
				break
			}
			m, _ := minimizeAny(item, depth+1, pol)
			out = append(out, m)
		}
		return out, trunc
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		trunc := false
		for k, item := range t {
			if !pol.AllowField(k) {
				trunc = true
				continue
			}
			m, _ := minimizeAny(item, depth+1, pol)
			out[k] = m
		}
		return out, trunc
	default:
		return "<unsupported>", true
	}
}

// marshalMinimized 序列化最小化后的值。标准库 encoding/json 保证输出合法，
// 总预算截断由调用方在字节层处理。
func marshalMinimized(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// MinimizeJSON 把任意 JSON 对象最小化后序列化；返回字节数与丢弃字段数。
// 任何单个字符串值都会过 ScrubTelemetryValue 与 MaxFieldLen。
func MinimizeJSON(obj map[string]interface{}) ([]byte, int, error) {
	pol := defaultReportPolicy()
	// 字符串值先全局 scrub（map 遍历内做），再递归深度/数组预算。
	scrubbed := make(map[string]interface{}, len(obj))
	var dropped int
	for k, v := range obj {
		if !pol.AllowField(k) {
			dropped++
			continue
		}
		scrubbed[k] = scrubJSONStrings(v, pol.MaxFieldLen)
	}
	minimized, _ := minimizeAny(scrubbed, 0, pol)
	data, err := marshalMinimized(minimized)
	if err != nil {
		return nil, dropped, err
	}
	if len(data) > pol.MaxBytes {
		data = data[:pol.MaxBytes]
	}
	return data, dropped, nil
}

// scrubJSONStrings 递归给 JSON 值里的每个字符串做值级去敏 + 长度上界。
func scrubJSONStrings(v interface{}, maxLen int) interface{} {
	switch t := v.(type) {
	case string:
		out := ScrubTelemetryValue(t)
		if len(out) > maxLen {
			out = out[:maxLen-3] + "..."
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, item := range t {
			out[i] = scrubJSONStrings(item, maxLen)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, item := range t {
			out[k] = scrubJSONStrings(item, maxLen)
		}
		return out
	default:
		return v
	}
}
