package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (a YamlHazardAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f YamlHazardFinding) bool { return !f.Blocking && f.Reason != yhReasonOK })
}

func (a YamlHazardAudit) Describe() string {
	return describeTaggedFindings("YAML 配置未发现构造风险", a.Findings, yhReasonOK, "yaml", yhMaxFindings,
		func(f YamlHazardFinding) string { return f.Reason },
		func(f YamlHazardFinding) string { return f.File },
		func(f YamlHazardFinding) string { return f.Detail })
}

func (a *YamlHazardAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, yhMaxFindings, YamlHazardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func yhCollect(root string) []string {
	found := []string{}
	entries, err := os.ReadDir(root)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		found = append(found, filepath.Join(root, name))
	}
	configDir := filepath.Join(root, "config")
	entries, err = os.ReadDir(configDir)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		found = append(found, filepath.Join(configDir, name))
	}
	sort.Strings(found)
	return found
}
