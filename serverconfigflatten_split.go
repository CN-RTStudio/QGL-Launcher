package main

import (
	"strings"
)

func cfgFlattenYAML(text string) map[string]string {
	out := map[string]string{}
	text = strings.TrimPrefix(text, "\ufeff")
	stack := make([]cfgYAMLFrame, 0, 8)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") || trimmed == "---" || trimmed == "..." {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if indent < len(line) && line[indent] == '\t' {
			continue
		}
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		key, value, ok := cfgYAMLKeyValue(strings.TrimSpace(line))
		if !ok {
			continue
		}
		full := key
		if len(stack) > 0 {
			parts := make([]string, 0, len(stack)+1)
			for _, frame := range stack {
				parts = append(parts, frame.key)
			}
			parts = append(parts, key)
			full = strings.Join(parts, ".")
		}
		value = cfgStripQuotes(cfgStripInlineComment(value))
		if _, exists := out[full]; !exists {
			out[full] = value
		}
		if value == "" {
			stack = append(stack, cfgYAMLFrame{indent: indent, key: key})
		}
	}
	return out
}

func cfgLookup(flat map[string]string, path string) (string, bool) {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return "", false
	}
	if value, ok := flat[path]; ok {
		return value, true
	}
	suffix := "." + path
	for key, value := range flat {
		if strings.HasSuffix(key, suffix) {
			return value, true
		}
	}
	return "", false
}
