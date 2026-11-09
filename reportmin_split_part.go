package main

import "strings"

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
