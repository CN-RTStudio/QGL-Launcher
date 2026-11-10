package main

import (
	"fmt"
	"sort"
	"strings"
)

func hasAny[T any](items []T) bool {
	return len(items) > 0
}
func anyBlocking[T any](items []T, isBlocking func(T) bool) bool {
	for _, item := range items {
		if isBlocking(item) {
			return true
		}
	}
	return false
}
func findingCodes[T any](items []T, reason func(T) string) []string {
	seen := make(map[string]struct{}, len(items))
	codes := make([]string, 0, len(items))
	for _, item := range items {
		r := reason(item)
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		codes = append(codes, r)
	}
	sort.Strings(codes)
	return codes
}
func describeFindings[T any](items []T, text func(T) string, limit int) string {
	lines := make([]string, 0, len(items))
	for _, item := range items {
		lines = append(lines, text(item))
	}
	sort.Strings(lines)
	if len(lines) > limit {
		lines = append(lines[:limit], fmt.Sprintf("...共%d项", len(items)))
	}
	return strings.Join(lines, "; ")
}

func jsonMaxDepth(data []byte) int {
	depth := 0
	max := 0
	inString := false
	escaped := false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return max
}

func jsonDuplicateKeys(data []byte) []string {
	dups := []string{}
	seen := map[string]int{}
	text := string(data)
	for {
		idx := strings.Index(text, "\"")
		if idx < 0 {
			break
		}
		rest := text[idx+1:]
		end := strings.Index(rest, "\"")
		if end < 0 {
			break
		}
		key := rest[:end]
		after := strings.TrimLeft(rest[end+1:], " \t\r\n")
		if strings.HasPrefix(after, ":") {
			seen[key]++
			if seen[key] == 2 {
				dups = append(dups, key)
			}
		}
		text = rest[end+1:]
	}
	return dups
}

func propsBoolValue(props map[string]string, key string) (bool, bool) {
	raw, ok := props[key]
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "on", "yes":
		return true, true
	case "false", "off", "no":
		return false, true
	}
	return false, false
}

func flatBoolValue(flat map[string]string, path string) (bool, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return false, false
	}
	switch strings.ToLower(cfgStripQuotes(value)) {
	case "true", "yes", "on", "1":
		return true, true
	case "false", "no", "off", "0":
		return false, true
	default:
		return false, false
	}
}

func hasControlCharsText(text string) bool {
	for _, r := range text {
		if r == '\t' || r == '\n' || r == '\r' {
			continue
		}
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
