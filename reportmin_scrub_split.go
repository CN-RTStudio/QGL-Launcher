package main

import (
	"strings"
)

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
