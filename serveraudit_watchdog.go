package main

import ()

const (
	spwMaxFindings      = 40
	spwMaxProps         = 256 * 1024
	spwMaxYAML          = 512 * 1024
	spwMinTimeout       = 60
	spwMaxTimeout       = 900
	spwReasonOK         = "ok"
	spwReasonMissing    = "missing"
	spwReasonSymlink    = "symlink"
	spwReasonTooLarge   = "too-large"
	spwReasonUnreadable = "unreadable"
	spwReasonDisabled   = "watchdog-disabled"
	spwReasonLow        = "watchdog-timeout-low"
	spwReasonHigh       = "watchdog-timeout-high"
	spwReasonBadValue   = "bad-value"
	spwReasonNoScript   = "restart-script-missing"
	spwReasonAbsPath    = "restart-script-absolute-path"
	spwReasonTraversal  = "restart-script-traversal"
	spwReasonMeta       = "restart-script-metacharacters"
	spwReasonEarlyOff   = "early-warning-disabled"
	spwReasonEarlyBad   = "early-warning-invalid"
	spwReasonRestartOff = "restart-on-crash-disabled"
)

type WatchdogFinding = auditFinding
type WatchdogAudit struct {
	ServerDir string
	Findings  []WatchdogFinding
}

func (a *WatchdogAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spwMaxFindings, WatchdogFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *WatchdogAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WatchdogFinding) bool { return f.Blocking })
}

func (a *WatchdogAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
