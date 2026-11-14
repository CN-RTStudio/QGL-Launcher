package main

import (
	"strings"
)

func tkLevelNameSafe(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	if trimmed == "." || trimmed == ".." {
		return false
	}
	if strings.Contains(trimmed, "..") {
		return false
	}
	if strings.ContainsAny(trimmed, "/\\") {
		return false
	}
	if len([]rune(trimmed)) > 64 {
		return false
	}
	return true
}
