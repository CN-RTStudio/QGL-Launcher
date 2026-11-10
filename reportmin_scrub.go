package main

import (
	"encoding/json"
	"strings"
)

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

func isWinDriveStart(s string, i int) bool {
	if i+1 < len(s) && (s[i+1] == ':') && isDriveLetter(s[i]) {
		if i+2 < len(s) && (s[i+2] == '\\' || s[i+2] == '/') {
			return true
		}
	}
	// UNC：\\host\share\…
	return i+1 < len(s) && s[i] == '\\' && s[i+1] == '\\'
}
func isDriveLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
func isSchemeChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-'
}
func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

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
func marshalMinimized(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

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
