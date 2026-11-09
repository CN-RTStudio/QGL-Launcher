package main

import "strings"

func scanUnsafeRunes(s string) string {
	for _, r := range s {
		if code := unsafeRuneCode(r); code != nameRejectNone {
			return code
		}
	}
	return nameRejectNone
}
func containsAnyByte(s string, set string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(set, s[i]) >= 0 {
			return true
		}
	}
	return false
}
func isReservedDeviceName(stem string) bool {
	st := strings.ToUpper(strings.TrimRight(stem, ". "))
	switch st {
	case "CON", "PRN", "AUX", "NUL":
		return true
	}
	if len(st) == 4 {
		prefix, digit := st[:3], st[3]
		if (prefix == "COM" || prefix == "LPT") && digit >= '1' && digit <= '9' {
			return true
		}
	}
	return false
}
func stemOfName(name string) string {
	if i := strings.IndexByte(name, '.'); i >= 0 {
		return name[:i]
	}
	return name
}
