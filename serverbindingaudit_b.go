package main

func (a *ServerBindingAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f BindingFinding) bool { return f.Blocking })
}

func (a *ServerBindingAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	return auditHasWarning(a.Findings, func(f BindingFinding) bool { return !f.Blocking && f.Reason != bindingReasonOK })
}

func (a *ServerBindingAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodesSkip(a.Findings, bindingReasonOK, func(f BindingFinding) string { return f.Reason })
}
