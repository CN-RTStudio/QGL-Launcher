package main

import "strings"

func scyValidAliasName(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, c := range value {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func scyCollectAliases(text string) []commandsYmlBlock {
	blocks := make([]commandsYmlBlock, 0, 8)
	var current *commandsYmlBlock
	inSection := false
	for _, line := range strings.Split(text, "\n") {
		raw := strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			inSection = trimmed == "aliases:" || strings.HasPrefix(trimmed, "aliases: ")
			current = nil
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			if current == nil {
				continue
			}
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			value = cfgStripQuotes(value)
			if strings.HasPrefix(value, "#") {
				continue
			}
			value = strings.TrimSpace(cfgStripInlineComment(value))
			if value != "" {
				current.Commands = append(current.Commands, value)
			}
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			name := cfgStripQuotes(strings.TrimSuffix(trimmed, ":"))
			current = &commandsYmlBlock{Name: name}
			blocks = append(blocks, *current)
			current = &blocks[len(blocks)-1]
		}
	}
	return blocks
}
