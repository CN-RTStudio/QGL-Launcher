package main

import (
	"strings"
)

func caSplitValue(raw string) []string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return nil
	}
	if strings.HasPrefix(text, "[") {
		text = strings.TrimSuffix(strings.TrimPrefix(text, "["), "]")
	}
	fields := strings.Split(text, ",")
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		token := strings.TrimSpace(field)
		token = strings.TrimPrefix(token, "-")
		token = strings.TrimSpace(token)
		token = strings.Trim(token, `"'`)
		if token != "" {
			out = append(out, token)
		}
	}
	return out
}

func caNormalizeAlias(name string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "/"))
}
