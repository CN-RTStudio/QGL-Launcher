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
	if len(a.Findings) >= sprMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PropertiesBudgetFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropertiesBudgetAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Blocking })
}

func (a *PropertiesBudgetAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if f.Reason != sprReasonOK && !f.Blocking {
			return true
		}
	}
	return false
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

func sprCheckInt(a *PropertiesBudgetAudit, props sprProperties, key string) (int, bool) {
	value, ok := props.Values[key]
	if !ok {
		return 0, false
	}
	n, valid := cfgParseInt(value)
	if !valid {
		a.add("server.properties", sprReasonBadValue, key+" 不是合法整数: "+value, false)
		return 0, false
	}
	return n, true
}

func sprCheckViewDistance(a *PropertiesBudgetAudit, props sprProperties) {
	view, hasView := sprCheckInt(a, props, "view-distance")
	simulation, hasSimulation := sprCheckInt(a, props, "simulation-distance")
	if hasView {
		if view > sprMaxViewDistance {
			a.add("server.properties", sprReasonViewLarge, fmt.Sprintf("view-distance=%d 超过 %d，区块与实体负载放大", view, sprMaxViewDistance), false)
		}
		if view < sprMinViewDistance {
			a.add("server.properties", sprReasonViewSmall, fmt.Sprintf("view-distance=%d 低于 %d", view, sprMinViewDistance), false)
		}
	}
	if hasSimulation && hasView && simulation > view {
		a.add("server.properties", sprReasonSimDistance, fmt.Sprintf("simulation-distance=%d 大于 view-distance=%d", simulation, view), false)
	}
}
