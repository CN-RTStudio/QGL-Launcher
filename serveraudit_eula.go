package main

import ()

const (
	serMaxFindings = 24
	serMaxFile     = 64 * 1024
	serReasonMiss  = "missing"
	serReasonLink  = "symlink"
	serReasonLarge = "too-large"
	serReasonRead  = "unreadable"
	serReasonEmpty = "empty-file"
	serReasonDecl  = "eula-not-accepted"
	serReasonDup   = "duplicate-eula-key"
	serReasonConf  = "conflicting-eula-values"
	serReasonCtl   = "control-characters"
)

type EulaFinding = auditFinding
type EulaAudit struct {
	ServerDir string
	Findings  []EulaFinding
}

func (a *EulaAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, serMaxFindings, EulaFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *EulaAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f EulaFinding) bool { return f.Blocking })
}
