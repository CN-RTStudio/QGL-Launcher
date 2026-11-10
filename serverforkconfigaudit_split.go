package main

func (a ForkConfigAudit) Describe() string {
	return describeTaggedFindings("服务端分支配置未发现风险", a.Findings, fkReasonOK, "fork-config", fkMaxFindings,
		func(f ForkConfigFinding) string { return f.Reason },
		func(f ForkConfigFinding) string { return f.File },
		func(f ForkConfigFinding) string { return f.Detail })
}
func (a *ForkConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, fkMaxFindings, ForkConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
