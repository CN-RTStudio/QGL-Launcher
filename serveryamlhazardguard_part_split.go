package main

import (
	"strings"
)

func yhHasTabIndent(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "\t") {
			return true
		}
		if strings.HasPrefix(line, " \t") {
			return true
		}
	}
	return false
}

func yhCountAliases(text string) int {
	count := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		colon := strings.Index(trimmed, ":")
		if colon >= 0 {
			value := strings.TrimSpace(trimmed[colon+1:])
			if strings.HasPrefix(value, "*") {
				count++
				continue
			}
		}
		if strings.HasPrefix(trimmed, "- *") {
			count++
		}
	}
	return count
}

func yhMaxAliasDepth(text string) int {
	anchors := 0
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "&") {
			parts := strings.SplitN(trimmed, "&", 2)
			if len(parts) == 2 && parts[1] != "" && !strings.HasPrefix(parts[1], "amp;") {
				anchors++
			}
		}
		if strings.Count(trimmed, "*") > 0 && strings.Contains(trimmed, ":") {
			value := strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:])
			if strings.HasPrefix(value, "*") {
				anchors++
			}
		}
	}
	return anchors
}

func yhDuplicateTopKeys(text string) int {
	counts := map[string]int{}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "-") {
			continue
		}
		colon := strings.Index(trimmed, ":")
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.Trim(strings.TrimSpace(trimmed[:colon]), `"'`))
		if key == "" {
			continue
		}
		counts[key]++
	}
	dups := 0
	for _, n := range counts {
		if n > 1 {
			dups++
		}
	}
	return dups
}

func AuditServerYamlHazards(serverDir string) YamlHazardAudit {
	audit := YamlHazardAudit{Dir: serverDir}
	if root := scanAuditRoot(serverDir, yhRootScan, yhCollect, func(root, path string) { yhInspectFile(&audit, root, path) }, audit.add, func() int { return len(audit.Findings) }); root != "" {
		audit.Dir = root
	}
	return audit
}
