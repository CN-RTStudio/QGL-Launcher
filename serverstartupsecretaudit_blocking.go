package main

func (a StartupSecretAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StartupSecretFinding) bool { return f.Blocking })
}

func (a StartupSecretAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f StartupSecretFinding) bool { return !f.Blocking && f.Reason != skReasonOK })
}

func (a StartupSecretAudit) Describe() string {
	return describeTaggedFindings("启动脚本未发现明文凭据", a.Findings, skReasonOK, "startup", skMaxFindings,
		func(f StartupSecretFinding) string { return f.Reason },
		func(f StartupSecretFinding) string { return f.File },
		func(f StartupSecretFinding) string { return f.Detail })
}

func (a *StartupSecretAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, skMaxFindings, StartupSecretFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
