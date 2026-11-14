package main

func (a BudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f BudgetFinding) bool { return !f.Blocking && f.Reason != bdReasonOK })
}

func (a BudgetAudit) Describe() string {
	return describeTaggedFindings("服务器磁盘占用未发现异常", a.Findings, bdReasonOK, "", bdMaxFindings,
		func(f BudgetFinding) string { return f.Reason },
		func(f BudgetFinding) string { return f.Area },
		func(f BudgetFinding) string { return f.Detail })
}

func (a *BudgetAudit) add(area, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, bdMaxFindings, BudgetFinding{Area: area, Reason: reason, Detail: detail, Blocking: blocking})
}
