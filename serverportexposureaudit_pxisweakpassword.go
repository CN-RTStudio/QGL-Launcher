package main

import (
	"strings"
)

func pxIsWeakPassword(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return true
	}
	if len([]rune(normalized)) < pxMinPasswordLength {
		return true
	}
	for _, weak := range pxWeakPasswords {
		if normalized == weak {
			return true
		}
	}
	unique := map[rune]struct{}{}
	for _, r := range normalized {
		unique[r] = struct{}{}
	}
	if len(unique) <= 3 {
		return true
	}
	return false
}
