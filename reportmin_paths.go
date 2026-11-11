package main

import (
	"encoding/json"
	"strings"
)

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
