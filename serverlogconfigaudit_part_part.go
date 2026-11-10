package main

func (a LogConfigAudit) Describe() string {
	return describeTaggedFindings("服务端日志配置未发现风险", a.Findings, lgReasonOK, "log-config", lgMaxFindings,
		func(f LogConfigFinding) string { return f.Reason },
		func(f LogConfigFinding) string { return f.File },
		func(f LogConfigFinding) string { return f.Detail })
}
func (a *LogConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, lgMaxFindings, LogConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
