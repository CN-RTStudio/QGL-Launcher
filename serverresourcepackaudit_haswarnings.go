package main

func (a *ServerResourcePackAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	return auditHasWarning(a.Findings, func(f PackFinding) bool { return !f.Blocking && f.Reason != packReasonOK })
}
