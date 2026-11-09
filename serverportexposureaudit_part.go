package main

import (
	"strconv"
	"strings"
)

func pxParseProperties(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		out[strings.ToLower(key)] = value
	}
	return out
}

func pxParsePort(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, false
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	if port < 1 || port > 65535 {
		return port, false
	}
	return port, true
}

func pxIsBindAll(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if value == "0.0.0.0" || value == "::" || value == "[::]" || value == "*" {
		return true
	}
	return false
}

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
