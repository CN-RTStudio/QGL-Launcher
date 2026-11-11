package main

import (
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
