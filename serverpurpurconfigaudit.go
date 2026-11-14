package main

import ()

const (
	spqMaxFindings = 32
	spqMaxFile     = 256 * 1024
	spqReasonMiss  = "missing"
	spqReasonLink  = "symlink"
	spqReasonLarge = "too-large"
	spqReasonRead  = "unreadable"
	spqReasonEmpty = "empty-config"
	spqReasonMsg   = "unsafe-message"
	spqReasonAllow = "permissive-toggle"
	spqReasonRate  = "tick-interval-zero"
	spqReasonJoin  = "join-limit-zero"
	spqReasonDup   = "duplicate-keys"
	spqReasonDep   = "deep-nesting"
	spqReasonOps   = "op-bypass-toggle"
)

type PurpurFinding = auditFinding

type PurpurAudit struct {
	ServerDir string
	Findings  []PurpurFinding
}

func (a *PurpurAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spqMaxFindings, PurpurFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
