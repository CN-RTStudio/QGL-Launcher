package main

import "strings"

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
