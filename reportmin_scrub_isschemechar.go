package main

import (
	"strings"
)

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
