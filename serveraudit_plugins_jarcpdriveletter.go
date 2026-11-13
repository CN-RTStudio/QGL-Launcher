package main

import (
	"strings"
	"unicode"
)

func jarCPDriveLetter(entry string) bool {
	if len(entry) < 2 || entry[1] != ':' {
		return false
	}
	c := entry[0]
	return unicode.IsLetter(rune(c)) && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z')
}
func jarCPIsAbsolute(entry string) bool {
	if strings.HasPrefix(entry, "/") || strings.HasPrefix(entry, `\\`) {
		return true
	}
	return jarCPDriveLetter(entry)
}
