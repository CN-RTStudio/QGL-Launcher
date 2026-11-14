package main

import (
	"strings"
)

func tkBool(props map[string]string, key string, fallback bool) bool {
	raw, ok := props[key]
	if !ok {
		return fallback
	}
	return strings.EqualFold(strings.TrimSpace(raw), "true")
}
