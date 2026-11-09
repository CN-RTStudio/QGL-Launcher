package main

import (
	"fmt"
	"strings"
)

func (a *PropertiesBudgetAudit) Describe() string {
	return describeFindings(a.Findings, func(f PropertiesBudgetFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

type sprProperties struct {
	Values     map[string]string
	Duplicates []string
	LongLines  int
}

func sprParseProperties(text string) sprProperties {
	out := sprProperties{Values: map[string]string{}}
	seen := map[string]bool{}
	text = strings.TrimPrefix(text, "\ufeff")
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		if len(line) > 4096 {
			out.LongLines++
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		if key == "" {
			continue
		}
		value := strings.TrimSpace(line[idx+1:])
		if seen[key] {
			out.Duplicates = append(out.Duplicates, key)
			continue
		}
		seen[key] = true
		out.Values[key] = value
	}
	return out
}
