package main

import ()

func (a PluginConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking })
}

func (a PluginConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
}

func (a PluginConfigAudit) Codes() []string {
	return findingCodesSkip(a.Findings, pcReasonOK, func(f PluginConfigFinding) string { return f.Reason })
}
