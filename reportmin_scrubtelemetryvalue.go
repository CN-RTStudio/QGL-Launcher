package main

import ()

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
