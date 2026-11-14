package main

import ()

const (
	ljMaxFindings      = 48
	ljMaxConfig        = 512 * 1024
	ljMaxJarName       = 128
	ljVulnVersion      = "2.17.0"
	ljReasonOK         = "ok"
	ljReasonMissing    = "missing"
	ljReasonVulnerable = "vulnerable-log4j"
	ljReasonJndiLookup = "jndi-lookup"
	ljReasonPattern    = "forced-lookup-pattern"
	ljReasonBadConfig  = "bad-config"
	ljReasonSymlink    = "symlink"
	ljReasonTooLarge   = "too-large"
	ljReasonBadName    = "bad-jar-name"
)

type Log4jFinding = auditFinding
type Log4jShellAudit struct {
	ServerDir string
	Jars      int
	Configs   int
	Findings  []Log4jFinding
}

func (a *Log4jShellAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ljMaxFindings, Log4jFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *Log4jShellAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f Log4jFinding) bool { return f.Blocking })
}
func (a *Log4jShellAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f Log4jFinding) bool { return f.Reason != ljReasonOK && !f.Blocking })
}
