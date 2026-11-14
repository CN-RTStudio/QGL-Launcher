package main

import (
	"strconv"
	"strings"
)

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
