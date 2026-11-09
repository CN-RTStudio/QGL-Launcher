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
