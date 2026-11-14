package main

import (
	"strings"
)

func jsonDuplicateKeys(data []byte) []string {
	dups := []string{}
	seen := map[string]int{}
	text := string(data)
	for {
		idx := strings.Index(text, "\"")
		if idx < 0 {
			break
		}
		rest := text[idx+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			break
		}
		key := rest[:end]
		after := strings.TrimLeft(rest[end+1:], " \t\r\n")
		if strings.HasPrefix(after, ":") {
			seen[key]++
			if seen[key] == 2 {
				dups = append(dups, key)
			}
		}
		text = rest[end+1:]
	}
	return dups
}

func propsBoolValue(props map[string]string, key string) (bool, bool) {
	raw, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "on", "yes":
		return true, true
	case "false", "off", "no":
		return false, true
	}
	return false, false
}
