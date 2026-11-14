package main

const (
	spgMaxFindings      = 36
	spgMaxConfig        = 256 * 1024
	spgMaxRadius        = 8192
	spgWarnRadius       = 4096
	spgReasonOK         = "ok"
	spgReasonMissing    = "missing"
	spgReasonSymlink    = "symlink"
	spgReasonTooLarge   = "too-large"
	spgReasonUnreadable = "unreadable"
	spgReasonNoConfig   = "config-missing"
	spgReasonRadius     = "radius-invalid"
	spgReasonRadiusBig  = "radius-too-large"
	spgReasonWorld      = "world-name-invalid"
	spgReasonTasksPath  = "task-world-path"
	spgReasonBadValue   = "bad-value"
	spgReasonSilent     = "silent-progress-disabled"
)

type PregenFinding = auditFinding
type PregenAudit struct {
	ServerDir string
	Findings  []PregenFinding
}

func (a *PregenAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spgMaxFindings, PregenFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PregenAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PregenFinding) bool { return f.Blocking })
}

func (a *PregenAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
