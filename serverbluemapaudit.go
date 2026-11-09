package main

const (
	sbmMaxFindings     = 36
	sbmMaxConfig       = 256 * 1024
	sbmMaxProps        = 256 * 1024
	sbmPrivilegedPort  = 1024
	sbmReasonOK        = "ok"
	sbmReasonMissing   = "missing"
	sbmReasonSymlink   = "symlink"
	sbmReasonTooLarge  = "too-large"
	sbmReasonUnread    = "unreadable"
	sbmReasonPort      = "webserver-port-invalid"
	sbmReasonPrivPort  = "webserver-port-privileged"
	sbmReasonPortClash = "webserver-port-conflict"
	sbmReasonBindAll   = "webserver-bind-all"
	sbmReasonDownload  = "accept-download-enabled"
	sbmReasonDataPath  = "data-path-escape"
	sbmReasonMetrics   = "metrics-enabled"
	sbmReasonRate      = "rate-limit-disabled"
	sbmReasonBadValue  = "bad-value"
)

type BlueMapFinding = auditFinding
type BlueMapAudit struct {
	ServerDir string
	Findings  []BlueMapFinding
}

func (a *BlueMapAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbmMaxFindings, BlueMapFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *BlueMapAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BlueMapFinding) bool { return f.Blocking })
}
func (a *BlueMapAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
