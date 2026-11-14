package main

import ()

const (
	sunMaxFindings      = 36
	sunMaxProps         = 256 * 1024
	sunMaxYAML          = 512 * 1024
	sunReasonOK         = "ok"
	sunReasonMissing    = "missing"
	sunReasonSymlink    = "symlink"
	sunReasonTooLarge   = "too-large"
	sunReasonUnreadable = "unreadable"
	sunReasonBadValue   = "bad-value"
	sunReasonSecureOff  = "secure-profile-off"
	sunReasonUsername   = "username-validation-off"
	sunReasonPermGen    = "perm-gen-allowed"
	sunReasonToggle     = "unsupported-toggle-enabled"
)

type UnsafeToggleFinding = auditFinding
type UnsafeToggleAudit struct {
	ServerDir string
	Findings  []UnsafeToggleFinding
}

func (a *UnsafeToggleAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sunMaxFindings, UnsafeToggleFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *UnsafeToggleAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f UnsafeToggleFinding) bool { return f.Blocking })
}
