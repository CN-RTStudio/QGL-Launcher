package main

import "strings"

func propsLookupBool(props map[string]string, key string) (bool, bool) {
	value, ok := props[strings.ToLower(key)]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}

func propsLookupInt(props map[string]string, key string) (int, bool, bool) {
	value, ok := props[strings.ToLower(key)]
	if !ok {
		return 0, false, false
	}
	n, valid := cfgParseInt(value)
	if !valid {
		return 0, true, false
	}
	return n, true, true
}

func propsValidName(value string) bool {
	if value == "" || len(value) > 16 {
		return false
	}
	for _, c := range value {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
