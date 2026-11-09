package main

import (
	"net"
	"strconv"
	"strings"
)

func remoteKeyCounts(data []byte) map[string]int {
	counts := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == '#' || trimmed[0] == '!' {
			continue
		}
		key, _, _, ok := splitPropertyPair(strings.TrimRight(line, "\r"))
		if !ok {
			continue
		}
		counts[key]++
	}
	return counts
}

func remoteBool(props *serverProperties, key string, fallback bool) bool {
	value, ok := props.Get(key)
	if !ok {
		return fallback
	}
	return remoteBoolValue(value, fallback)
}

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

func remoteWildcardIP(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.IsUnspecified()
	}
	for _, wildcard := range remoteWildcardBindings {
		if value == wildcard {
			return true
		}
	}
	return false
}
