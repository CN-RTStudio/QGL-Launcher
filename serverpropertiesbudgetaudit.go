package main

import (
	"fmt"
	"strings"
)

const (
	sprMaxFindings       = 48
	sprMaxProps          = 256 * 1024
	sprMaxViewDistance   = 16
	sprMinViewDistance   = 3
	sprMaxCompression    = 1024
	sprReasonOK          = "ok"
	sprReasonMissing     = "missing"
	sprReasonSymlink     = "symlink"
	sprReasonTooLarge    = "too-large"
	sprReasonUnreadable  = "unreadable"
	sprReasonBadConfig   = "bad-config"
	sprReasonBadValue    = "bad-value"
	sprReasonDupKey      = "duplicate-key"
	sprReasonViewLarge   = "view-distance-large"
	sprReasonViewSmall   = "view-distance-small"
	sprReasonSimDistance = "simulation-exceeds-view"
	sprReasonCompression = "compression-threshold"
	sprReasonWatchdog    = "watchdog-disabled"
	sprReasonPortClash   = "port-conflict"
	sprReasonLevelName   = "level-name-traversal"
	sprReasonPackURL     = "insecure-resource-pack"
)

type PropertiesBudgetFinding = auditFinding

type PropertiesBudgetAudit struct {
	ServerDir string
	Keys      int
	Findings  []PropertiesBudgetFinding
}

func (a *PropertiesBudgetAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sprMaxFindings, PropertiesBudgetFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropertiesBudgetAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Blocking })
}

func (a *PropertiesBudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Reason != sprReasonOK && !f.Blocking })
}

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
