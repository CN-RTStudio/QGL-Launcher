package main

import (
	"strings"
)

func propTruthy(props *serverProperties, key string) bool {
	raw, ok := props.Get(key)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}
