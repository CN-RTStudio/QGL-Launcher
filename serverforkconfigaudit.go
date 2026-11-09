package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	fkReasonOK              = "ok"
	fkReasonMissing         = "missing-all"
	fkReasonSymlink         = "symlink"
	fkReasonTooLarge        = "too-large"
	fkReasonWorldWritable   = "world-writable"
	fkReasonUnreadable      = "unreadable"
	fkReasonThrottleOff     = "connection-throttle-off"
	fkReasonLegacyProxy     = "legacy-proxy-enabled"
	fkReasonProxySecret     = "proxy-secret-missing"
	fkReasonXrayOff         = "anti-xray-off"
	fkReasonPacketLimiter   = "packet-limiter-off"
	fkReasonPacketRate      = "max-packet-rate-high"
	fkReasonCollisions      = "max-entity-collisions-high"
	fkReasonActivationRange = "activation-range-high"
	fkReasonViewDistance    = "view-distance-high"
	fkReasonSaveInterval    = "autosave-interval-high"
	fkReasonIdleTimeout     = "idle-timeout-zero"
	fkReasonUnknownValue    = "non-numeric-value"

	fkMaxConfigBytes = 2 << 20
	fkMaxFindings    = 48
)

var fkConfigFiles = []string{
	"bukkit.yml",
	"spigot.yml",
	"paper.yml",
	"config/paper-global.yml",
	"config/paper-world-defaults.yml",
}

type ForkConfigFinding = auditFinding

type ForkConfigAudit struct {
	Dir      string
	Files    []string
	Findings []ForkConfigFinding
}

func (a ForkConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ForkConfigFinding) bool { return f.Blocking })
}

func (a ForkConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ForkConfigFinding) bool { return !f.Blocking && f.Reason != fkReasonOK })
}

func (a ForkConfigAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == fkReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "fork-config"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= fkMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务端分支配置未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *ForkConfigAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= fkMaxFindings {
		return
	}
	a.Findings = append(a.Findings, ForkConfigFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func fkFlattenConfig(text string) map[string]string {
	props := map[string]string{}
	stackKeys := []string{}
	stackIndent := []int{}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		for len(stackIndent) > 0 && indent <= stackIndent[len(stackIndent)-1] {
			stackIndent = stackIndent[:len(stackIndent)-1]
			stackKeys = stackKeys[:len(stackKeys)-1]
		}
		colon := strings.Index(trimmed, ":")
		if colon <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(trimmed[:colon]), `"'`)
		value := strings.TrimSpace(trimmed[colon+1:])
		if key == "" {
			continue
		}
		if strings.HasPrefix(value, "#") {
			continue
		}
		if value == "" {
			stackIndent = append(stackIndent, indent)
			stackKeys = append(stackKeys, strings.ToLower(key))
			continue
		}
		parts := append(append([]string{}, stackKeys...), strings.ToLower(key))
		props[strings.Join(parts, ".")] = value
	}
	return props
}
