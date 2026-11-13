package main

import (
	"strings"
)

func sqbPort(props map[string]string, key string) (int, bool, bool) {
	return propsLookupInt(props, key)
}

func sqbIsWildcardHost(host string) bool {
	host = strings.TrimSpace(host)
	switch host {
	case "", "0.0.0.0", "::", "[::]", "*":
		return true
	}
	return false
}

func sqbHostLooksInvalid(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if strings.ContainsAny(host, "/\\") || strings.Contains(host, "://") {
		return true
	}
	if strings.ContainsAny(host, " \t") {
		return true
	}
	if strings.Contains(host, "@") || strings.Contains(host, "?") || strings.Contains(host, "#") {
		return true
	}
	return false
}
