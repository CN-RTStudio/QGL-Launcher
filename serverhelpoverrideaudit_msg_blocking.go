package main

import ()

func (a HelpOverrideAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f HelpOverrideFinding) bool { return f.Blocking })
}

func (a HelpOverrideAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f HelpOverrideFinding) bool { return !f.Blocking && f.Reason != hoReasonOK })
}
