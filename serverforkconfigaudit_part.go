package main

import (
	"strconv"
	"strings"
)

func fkNumber(props map[string]string, key string) (int, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		value, err := strconv.Atoi(strings.TrimSpace(strings.Trim(raw, `"'`)))
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}
func fkBool(props map[string]string, key string) (bool, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		normalized := strings.ToLower(strings.TrimSpace(strings.Trim(raw, `"'`)))
		switch normalized {
		case "true", "yes", "on":
			return true, true
		case "false", "no", "off":
			return false, true
		}
		return false, false
	}
	return false, false
}
func fkString(props map[string]string, key string) (string, bool) {
	for _, candidate := range fkKeyVariants(key) {
		raw, ok := props[candidate]
		if !ok {
			continue
		}
		return strings.Trim(strings.TrimSpace(raw), `"'`), true
	}
	return "", false
}
