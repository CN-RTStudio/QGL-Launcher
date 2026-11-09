package main

import "strings"

func pjDescriptorName(entries map[string]bool) string {
	for _, name := range []string{"plugin.yml", "paper-plugin.yml", "bungee.yml", "velocity-plugin.json"} {
		if entries[name] {
			return name
		}
	}
	return ""
}
func pjMainClass(descriptor, body string) (string, bool) {
	if strings.HasSuffix(descriptor, ".json") {
		const key = "\"main\""
		idx := strings.Index(body, key)
		if idx < 0 {
			return "", false
		}
		rest := body[idx+len(key):]
		colon := strings.Index(rest, ":")
		if colon < 0 {
			return "", false
		}
		rest = rest[colon+1:]
		quote := strings.Index(rest, "\"")
		if quote < 0 {
			return "", false
		}
		rest = rest[quote+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			return "", false
		}
		return strings.TrimSpace(rest[:end]), true
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "main:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "main:"))
		value = strings.Trim(value, "'\"")
		return value, true
	}
	return "", false
}
func pjMainLooksBad(main string) (bad, shelly bool) {
	if main == "" {
		return true, false
	}
	if len(main) > pjMaxMainLen {
		return true, false
	}
	if strings.Contains(main, "..") || strings.HasPrefix(main, "/") || strings.ContainsAny(main, " \t") {
		return true, false
	}
	dots := strings.Count(main, ".")
	if dots < 1 {
		return true, false
	}
	lower := strings.ToLower(main)
	for _, token := range pjShellyMainTokens {
		if strings.Contains(lower, token) {
			return false, true
		}
	}
	return false, false
}
