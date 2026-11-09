package main

import (
	"strings"
)

const (
	pacMaxFindings   = 36
	pacMaxFile       = 256 * 1024
	pacMinSecret     = 12
	pacMaxSends      = 100
	pacMaxJoins      = 50
	pacReasonMiss    = "missing"
	pacReasonLink    = "symlink"
	pacReasonLarge   = "too-large"
	pacReasonRead    = "unreadable"
	pacReasonEmpty   = "empty-config"
	pacReasonSecret  = "velocity-secret-weak"
	pacReasonOffline = "proxy-offline-mode"
	pacReasonKick    = "unsafe-kick-message"
	pacReasonSends   = "chunk-send-budget-too-high"
	pacReasonJoins   = "join-budget-too-high"
	pacReasonCollide = "player-collisions-disabled"
)

type PaperFinding = auditFinding

type PaperAudit struct {
	ServerDir string
	Findings  []PaperFinding
}

func (a *PaperAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pacMaxFindings, PaperFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PaperAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PaperFinding) bool { return f.Blocking })
}

func (a *PaperAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PaperAudit) Describe() string {
	return describeFileReasonDetail("Paper 全局配置未发现风险", a.Findings, 12)
}

func pacHasControlChars(text string) bool {
	return hasControlCharsText(text)
}

func pacParseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on", "1":
		return true
	}
	return false
}

func pacSecretWeak(secret string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(secret))
	if trimmed == "" || len(trimmed) < pacMinSecret {
		return true
	}
	for _, placeholder := range []string{"changeme", "change-me", "secret", "password", "your-secret", "<secret>", "velocity-secret"} {
		if trimmed == placeholder || strings.HasPrefix(trimmed, placeholder) {
			return true
		}
	}
	return false
}
