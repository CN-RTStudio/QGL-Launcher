package main

func (a PermissionConfigAudit) Describe() string {
	return describeTaggedFindings("权限配置未发现越权授予", a.Findings, pmReasonOK, "permissions", pmMaxFindings,
		func(f PermissionConfigFinding) string { return f.Reason },
		func(f PermissionConfigFinding) string { return f.File },
		func(f PermissionConfigFinding) string { return f.Detail })
}
func (a *PermissionConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pmMaxFindings, PermissionConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
