package main

func (a ServerPortAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ServerPortFinding) bool { return f.Blocking })
}

func (a ServerPortAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ServerPortFinding) bool { return !f.Blocking && f.Reason != pxReasonOK })
}

func (a ServerPortAudit) Describe() string {
	return describeTaggedFindings("服务端端口与绑定配置未发现风险", a.Findings, pxReasonOK, "server.properties", pxMaxFindings,
		func(f ServerPortFinding) string { return f.Reason },
		func(f ServerPortFinding) string { return f.File },
		func(f ServerPortFinding) string { return f.Detail })
}

func (a *ServerPortAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pxMaxFindings, ServerPortFinding{File: a.File, Reason: reason, Detail: detail, Blocking: blocking})
}
