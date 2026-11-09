package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	tkReasonOK              = "ok"
	tkReasonMissing         = "missing"
	tkReasonUnreadable      = "unreadable"
	tkReasonSymlink         = "symlink"
	tkReasonWatchdogOff     = "watchdog-disabled"
	tkReasonTickBudget      = "tick-budget"
	tkReasonUnsafeSave      = "unsafe-save"
	tkReasonPlayerLimit     = "player-limit"
	tkReasonCompression     = "compression-threshold"
	tkReasonViewDistance    = "view-distance"
	tkReasonSimulation      = "simulation-distance"
	tkReasonBroadcast       = "broadcast-range"
	tkReasonCollisions      = "entity-collisions"
	tkReasonIdleTimeout     = "idle-timeout"
	tkReasonSpawnProtection = "spawn-protection"
	tkReasonResourcePack    = "required-resource-pack"
	tkReasonLevelName       = "unsafe-level-name"
	tkReasonStatusOff       = "status-hidden"
	tkReasonTooLarge        = "too-large"

	tkMaxPropertiesBytes = 1 << 20
	tkMaxFindings        = 48
	tkMinTickBudget      = 1000
	tkMaxTickBudget      = 600000
	tkMaxPlayersBudget   = 200
	tkMaxViewDistance    = 16
	tkMaxBroadcast       = 200
	tkMaxCollisions      = 8
)

type TickConfigFinding = auditFinding

type TickConfigAudit struct {
	Dir      string
	File     string
	Props    map[string]string
	Findings []TickConfigFinding
}

func (a TickConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TickConfigFinding) bool { return f.Blocking })
}

func (a TickConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f TickConfigFinding) bool { return !f.Blocking && f.Reason != tkReasonOK })
}

func (a TickConfigAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == tkReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= tkMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务端运行参数未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *TickConfigAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, tkMaxFindings, TickConfigFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func tkInt(props map[string]string, key string, fallback int) int {
	raw, ok := props[key]
	if !ok {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}

func tkBool(props map[string]string, key string, fallback bool) bool {
	raw, ok := props[key]
	if !ok {
		return fallback
	}
	return strings.EqualFold(strings.TrimSpace(raw), "true")
}

func tkLevelNameSafe(name string) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	if trimmed == "." || trimmed == ".." {
		return false
	}
	if strings.Contains(trimmed, "..") {
		return false
	}
	if strings.ContainsAny(trimmed, "/\\") {
		return false
	}
	if len([]rune(trimmed)) > 64 {
		return false
	}
	return true
}
