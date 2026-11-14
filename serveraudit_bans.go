package main

import ()

const (
	sbeMaxFindings = 22
	sbeMaxFile     = 512 * 1024
	sbeBadJSON     = "ban-json-invalid"
	sbeNoUUID      = "ban-entry-without-uuid"
	sbeNoReason    = "ban-entry-without-reason"
	sbeOpBanned    = "operator-also-banned"
	sbeWildcard    = "ip-ban-wildcard"
	sbeDupEntry    = "ban-duplicate"
	sbeLink        = "ban-file-symlink"
)

type BanEnforcementFinding = auditFinding
type BanEnforcementAudit struct {
	ServerDir string
	Findings  []BanEnforcementFinding
}

func (a *BanEnforcementAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbeMaxFindings, BanEnforcementFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *BanEnforcementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BanEnforcementFinding) bool { return f.Blocking })
}
func (a *BanEnforcementAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
