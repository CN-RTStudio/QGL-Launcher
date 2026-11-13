package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
