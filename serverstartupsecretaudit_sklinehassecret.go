package main

import (
	"strings"
)

func skLineHasSecret(line string) bool {
	for _, key := range skSecretKeys {
		needle := key + "="
		idx := strings.Index(line, needle)
		if idx < 0 {
			continue
		}
		value := strings.TrimSpace(line[idx+len(needle):])
		value = strings.Trim(value, "\"'`")
		if value == "" || strings.HasPrefix(value, "$") || strings.HasPrefix(value, "%") {
			continue
		}
		if strings.HasPrefix(value, "${") || strings.HasPrefix(value, "<") {
			continue
		}
		return true
	}
	return false
}
