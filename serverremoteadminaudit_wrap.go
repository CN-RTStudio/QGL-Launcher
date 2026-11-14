package main

import (
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
