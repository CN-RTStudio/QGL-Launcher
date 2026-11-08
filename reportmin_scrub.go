package main

import "strings"

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
