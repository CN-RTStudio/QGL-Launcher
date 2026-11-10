package main

func (a AccessControlAudit) Describe() string {
	return describeTaggedFindings("访问控制未发现风险", a.Findings, acReasonOK, "server", acMaxFindings,
		func(f AccessControlFinding) string { return f.Reason },
		func(f AccessControlFinding) string { return f.File },
		func(f AccessControlFinding) string { return f.Detail })
}
