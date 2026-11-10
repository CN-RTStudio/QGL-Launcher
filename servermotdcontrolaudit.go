package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	smcMaxFindings  = 14
	smcMaxFile      = 256 * 1024
	smcMaxRunes     = 256
	smcMaxSection   = 32
	smcMiss         = "motd-missing"
	smcRead         = "motd-unreadable"
	smcLink         = "properties-symlink"
	smcEmpty        = "motd-empty"
	smcControl      = "motd-control-character"
	smcNewline      = "motd-line-break"
	smcBidi         = "motd-bidi-override"
	smcZeroWidth    = "motd-zero-width"
	smcTooLong      = "motd-too-long"
	smcSection      = "motd-section-code-invalid"
	smcSectionDense = "motd-section-code-dense"
	smcMalformed    = "properties-line-malformed"
	smcKeySpace     = "properties-key-whitespace"
)

type MotdControlFinding = auditFinding
type MotdControlAudit struct {
	ServerDir string
	Findings  []MotdControlFinding
}

func (a *MotdControlAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smcMaxFindings, MotdControlFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *MotdControlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f MotdControlFinding) bool { return f.Blocking })
}
func (a *MotdControlAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *MotdControlAudit) Describe() string {
	return describeAuditFindings("服务器 MOTD 文本未发现控制字符风险", a.Findings, 10,
		func(f MotdControlFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f MotdControlFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func smcReadLines(serverDir string, a *MotdControlAudit) ([]string, bool) {
	path := filepath.Join(serverDir, "server.properties")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(smcMiss, "缺少 server.properties", false)
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(smcRead, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(smcLink, "属性文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, smcMaxFile)
	if err != nil {
		a.add(smcRead, err.Error(), true)
		return nil, false
	}
	text := strings.TrimPrefix(string(data), "\ufeff")
	return strings.Split(text, "\n"), true
}

func smcSectionRune(r rune) bool {
	if r >= '0' && r <= '9' {
		return true
	}
	lower := r
	if lower >= 'A' && lower <= 'Z' {
		lower = lower + ('a' - 'A')
	}
	switch lower {
	case 'a', 'b', 'c', 'd', 'e', 'f', 'k', 'l', 'm', 'n', 'o', 'r':
		return true
	}
	return false
}

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
