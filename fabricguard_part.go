package main

import "strings"

func isPrereleaseSuffix(s string) bool {
	if len(s) < 2 || s[0] != '-' {
		return false
	}
	rest := s[1:]
	for _, prefix := range []string{"alpha", "beta", "rc", "pre"} {
		if strings.HasPrefix(rest, prefix) {
			num := rest[len(prefix):]
			if num == "" {
				return true // -beta 允许不带数字
			}
			return isDigits(num)
		}
	}
	return false
}

// isDottedNumber 校验形如 1 / 1.19 / 0.14.24 的数字点段串。
func isDottedNumber(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 8 {
		return false
	}
	for _, p := range parts {
		if p == "" || !isDigits(p) {
			return false
		}
	}
	return true
}

// isDigits 校验纯数字串（允许前导零）。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
