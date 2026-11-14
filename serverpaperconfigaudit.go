package main

import ()

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
