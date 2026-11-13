package main

import (
	"sort"
	"strings"
)

func spxKeysWithSuffix(flat map[string]string, suffixes []string) []string {
	out := make([]string, 0, 16)
	for key := range flat {
		leaf := key
		if idx := strings.LastIndex(key, "."); idx >= 0 {
			leaf = key[idx+1:]
		}
		for _, suffix := range suffixes {
			if leaf == suffix {
				out = append(out, key)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func spxBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	}
	return false, false
}

func spxURLRisk(value string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return "empty", false
	}
	if strings.HasPrefix(lower, "http://") {
		return "cleartext", true
	}
	if strings.HasPrefix(lower, "ftp://") || strings.HasPrefix(lower, "file://") {
		return "local-or-legacy", true
	}
	at := strings.Index(lower, "@")
	if at > 0 {
		scheme := strings.Index(lower, "://")
		if scheme > 0 && at > scheme {
			return "credentials", true
		}
	}
	if strings.Contains(lower, "\\") || strings.Contains(lower, "..") {
		return "path-shape", true
	}
	return "https", false
}
