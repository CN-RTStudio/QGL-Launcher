package main

import (
	"sort"
	"strings"
)

func scbScanSpamExclusions(text string) []string {
	lines := strings.Split(text, "\n")
	items := make([]string, 0, 16)
	inSection := false
	baseIndent := 0
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		if !inSection {
			if strings.HasPrefix(trimmed, "spam-exclusions:") {
				inSection = true
				baseIndent = indent
			}
			continue
		}
		if indent <= baseIndent && !strings.HasPrefix(trimmed, "-") {
			break
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			value = cfgStripQuotes(value)
			if value != "" {
				items = append(items, value)
			}
		}
	}
	return items
}
func scbCheckWorldSettings(a *CommandBlockAudit, flat map[string]string) {
	keys := make([]string, 0, len(flat))
	for key := range flat {
		if strings.HasSuffix(key, "command-block-output") || strings.HasSuffix(key, "command-blocks-enabled") {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		return
	}
	for _, key := range keys {
		value := strings.ToLower(strings.TrimSpace(flat[key]))
		if key == "world-settings.default.command-blocks-enabled" && value != "true" {
			a.add("spigot.yml", scbReasonNoBlock, "world-settings.default.command-blocks-enabled=false，世界级命令方块禁用", false)
		}
	}
}
