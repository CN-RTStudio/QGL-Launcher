package main

const (
	sprMaxFindings       = 48
	sprMaxProps          = 256 * 1024
	sprMaxViewDistance   = 16
	sprMinViewDistance   = 3
	sprMaxCompression    = 1024
	sprReasonOK          = "ok"
	sprReasonMissing     = "missing"
	sprReasonSymlink     = "symlink"
	sprReasonTooLarge    = "too-large"
	sprReasonUnreadable  = "unreadable"
	sprReasonBadConfig   = "bad-config"
	sprReasonBadValue    = "bad-value"
	sprReasonDupKey      = "duplicate-key"
	sprReasonViewLarge   = "view-distance-large"
	sprReasonViewSmall   = "view-distance-small"
	sprReasonSimDistance = "simulation-exceeds-view"
	sprReasonCompression = "compression-threshold"
	sprReasonWatchdog    = "watchdog-disabled"
	sprReasonPortClash   = "port-conflict"
	sprReasonLevelName   = "level-name-traversal"
	sprReasonPackURL     = "insecure-resource-pack"
)

type PropertiesBudgetFinding = auditFinding
type PropertiesBudgetAudit struct {
	ServerDir string
	Keys      int
	Findings  []PropertiesBudgetFinding
}

func (a *PropertiesBudgetAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sprMaxFindings, PropertiesBudgetFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PropertiesBudgetAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Blocking })
}
func (a *PropertiesBudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PropertiesBudgetFinding) bool { return f.Reason != sprReasonOK && !f.Blocking })
}
