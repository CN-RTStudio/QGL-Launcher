package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func smcIsBidi(r rune) bool {
	return (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069') || r == '\u200f' || r == '\u200e'
}

func smcIsZeroWidth(r rune) bool {
	return r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\ufeff'
}

func AuditServerMotdControl(serverDir string) *MotdControlAudit {
	a := &MotdControlAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(smcMiss, "未配置服务器目录", false)
		return a
	}
	lines, ok := smcReadLines(serverDir, a)
	if !ok {
		return a
	}
	motd := ""
	motdSet := false
	seen := map[string]bool{}
	for index, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			if seen[smcMalformed] {
				continue
			}
			seen[smcMalformed] = true
			a.add(smcMalformed, fmt.Sprintf("第 %d 行不是 key=value 结构", index+1), false)
			continue
		}
		key := line[:eq]
		if strings.TrimSpace(key) != key {
			if !seen[smcKeySpace] {
				seen[smcKeySpace] = true
				a.add(smcKeySpace, fmt.Sprintf("第 %d 行的键存在首尾空白", index+1), false)
			}
		}
		if key == "motd" {
			motd = line[eq+1:]
			motdSet = true
		}
	}
	if !motdSet || strings.TrimSpace(motd) == "" {
		a.add(smcEmpty, "MOTD 为空，服务器列表暴露默认描述", false)
		return a
	}
	if strings.ContainsAny(motd, "\r\n") {
		a.add(smcNewline, "MOTD 含换行，客户端列表解析可能被截断", true)
	}
	sectionCount := 0
	runes := []rune(motd)
	for i, r := range runes {
		if r < 0x20 || r == 0x7f {
			if !seen[smcControl] {
				seen[smcControl] = true
				a.add(smcControl, fmt.Sprintf("第 %d 个字符是控制字符 U+%04X", i+1, r), true)
			}
			continue
		}
		if smcIsBidi(r) {
			if !seen[smcBidi] {
				seen[smcBidi] = true
				a.add(smcBidi, "MOTD 含双向控制字符，可伪装显示顺序", true)
			}
			continue
		}
		if smcIsZeroWidth(r) {
			if !seen[smcZeroWidth] {
				seen[smcZeroWidth] = true
				a.add(smcZeroWidth, "MOTD 含零宽字符，可隐藏真实文本", false)
			}
			continue
		}
		if r == '\u00a7' {
			sectionCount++
			if i+1 >= len(runes) || !smcSectionRune(runes[i+1]) {
				if !seen[smcSection] {
					seen[smcSection] = true
					a.add(smcSection, "§ 后缺少合法格式码", false)
				}
			}
		}
	}
	if utf8.RuneCountInString(motd) > smcMaxRunes {
		a.add(smcTooLong, fmt.Sprintf("MOTD 长度 %d 超出上限 %d", utf8.RuneCountInString(motd), smcMaxRunes), false)
	}
	if sectionCount > smcMaxSection {
		a.add(smcSectionDense, fmt.Sprintf("格式码数量 %d 过多，客户端渲染开销异常", sectionCount), false)
	}
	return a
}
