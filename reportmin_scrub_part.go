package main

import (
	"strings"
)

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
