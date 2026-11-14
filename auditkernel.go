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
