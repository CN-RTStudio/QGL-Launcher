package main

import (
	"strconv"
	"strings"
)

func remoteBoolValue(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true
	case "false", "no", "off", "0":
		return false
	}
	return fallback
}

func remotePort(value string) (int, bool) {
	trimmed := strings.TrimSpace(value)
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] < '0' || trimmed[i] > '9' {
			return 0, false
		}
	}
	if len(trimmed) > 1 && trimmed[0] == '0' {
		return 0, false
	}
	port, err := strconv.Atoi(trimmed)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func remoteWeakPassword(value string) bool {
	lower := strings.ToLower(value)
	for _, weak := range remoteWeakPasswords {
		if lower == weak {
			return true
		}
	}
	return false
}
