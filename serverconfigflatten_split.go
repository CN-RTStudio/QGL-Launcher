package main

import (
	"strconv"
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

func cfgParseInt(value string) (int, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	negative := false
	if strings.HasPrefix(value, "+") {
		value = value[1:]
	} else if strings.HasPrefix(value, "-") {
		negative = true
		value = value[1:]
	}
	if value == "" {
		return 0, false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	if negative {
		n = -n
	}
	return n, true
}

func cfgIsPlaceholder(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") {
		return true
	}
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		return true
	}
	switch value {
	case "secret", "password", "changeme", "change-me", "change_me", "todo", "tbd", "xxx", "none", "null", "undefined", "default":
		return true
	}
	return false
}

func cfgHasControlChars(value string) bool {
	for _, r := range value {
		if r < 0x20 && r != '\t' {
			return true
		}
		if r == 0x7f {
			return true
		}
	}
	return false
}
