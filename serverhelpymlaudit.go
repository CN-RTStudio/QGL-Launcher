package main

import ()

const (
	shyMaxFindings = 32
	shyMaxFile     = 256 * 1024
	shyMaxTopics   = 128
	shyMaxLine     = 256
	shyReasonMiss  = "missing"
	shyReasonLink  = "symlink"
	shyReasonLarge = "too-large"
	shyReasonRead  = "unreadable"
	shyReasonEmpty = "empty-config"
	shyReasonTag   = "unsafe-yaml-tag"
	shyReasonCtl   = "control-characters"
	shyReasonTopic = "too-many-topics"
	shyReasonLong  = "overlong-topic"
	shyReasonObfus = "obfuscated-formatting"
)

type HelpYmlFinding = auditFinding
type HelpYmlAudit struct {
	ServerDir string
	Findings  []HelpYmlFinding
}

func (a *HelpYmlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, shyMaxFindings, HelpYmlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *HelpYmlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f HelpYmlFinding) bool { return f.Blocking })
}
