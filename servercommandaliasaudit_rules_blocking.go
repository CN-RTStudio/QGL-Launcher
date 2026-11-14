package main

import ()

func (a CommandAliasAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CommandAliasFinding) bool { return f.Blocking })
}

func (a CommandAliasAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f CommandAliasFinding) bool { return !f.Blocking && f.Reason != caReasonOK })
}
