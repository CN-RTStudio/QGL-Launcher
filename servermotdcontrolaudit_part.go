package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
