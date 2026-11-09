package main

import (
	"strings"
)

type cfgYAMLFrame struct {
	indent int
	key    string
}

func cfgStripQuotes(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		first := value[0]
		last := value[len(value)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func cfgStripInlineComment(value string) string {
	inSingle := false
	inDouble := false
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if inSingle || inDouble {
				continue
			}
			if i == 0 || value[i-1] == ' ' || value[i-1] == '\t' {
				return strings.TrimRight(value[:i], " \t")
			}
		}
	}
	return strings.TrimRight(value, " \t")
}

func cfgYAMLKeyValue(line string) (string, string, bool) {
	if strings.HasPrefix(line, "-") {
		return "", "", false
	}
	idx := -1
	inSingle := false
	inDouble := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if inSingle || inDouble {
				continue
			}
			if i+1 == len(line) || line[i+1] == ' ' || line[i+1] == '\t' {
				idx = i
			}
		}
		if idx >= 0 {
			break
		}
	}
	if idx <= 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	if key == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	value := line[idx+1:]
	return strings.ToLower(key), value, true
}
