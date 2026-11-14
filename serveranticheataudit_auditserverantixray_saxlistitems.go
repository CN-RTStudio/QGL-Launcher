package main

import (
	"strings"
)

func saxListItems(text, key string) []string {
	lines := strings.Split(text, "\n")
	items := []string{}
	found := -1
	baseIndent := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if found < 0 {
			colon := strings.Index(trimmed, ":")
			if colon < 0 {
				continue
			}
			name := strings.TrimSpace(trimmed[:colon])
			if name != key {
				continue
			}
			rest := strings.TrimSpace(trimmed[colon+1:])
			if rest != "" && rest != "[]" {
				continue
			}
			found = i
			baseIndent = saxIndent(line)
			continue
		}
		if saxIndent(line) <= baseIndent {
			break
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		items = append(items, cfgStripQuotes(item))
		if len(items) > 256 {
			break
		}
	}
	return items
}
