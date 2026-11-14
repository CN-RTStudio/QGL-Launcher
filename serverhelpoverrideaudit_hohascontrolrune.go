package main

import (
	"strings"
	"unicode"
)

func hoHasControlRune(text string) bool {
	for _, r := range text {
		if r == '\n' || r == '\r' || r == '\t' {
			continue
		}
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
func hoHasRemoteURL(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
}
