package main

import (
	"strings"
)

func spgListItems(text, key string) []string {
	lines := strings.Split(text, "\n")
	items := []string{}
	baseIndent := -1
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if baseIndent < 0 {
			colon := strings.Index(trimmed, ":")
			if colon < 0 {
				continue
			}
			if strings.TrimSpace(trimmed[:colon]) != key {
				continue
			}
			if strings.TrimSpace(trimmed[colon+1:]) != "" {
				continue
			}
			baseIndent = saxIndent(line)
			continue
		}
		if saxIndent(line) <= baseIndent {
			break
		}
		if !strings.HasPrefix(trimmed, "- ") {
			break
		}
		items = append(items, cfgStripQuotes(strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))))
		if len(items) > 128 {
			break
		}
	}
	return items
}
