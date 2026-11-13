package main

func (a IconAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f IconFinding) bool { return !f.Blocking && f.Reason != iconReasonOK })
}

func (a IconAudit) Codes() []string {
	return findingCodesSkip(a.Findings, iconReasonOK, func(f IconFinding) string { return f.Reason })
}

func (a IconAudit) Describe() string {
	return describeLabeledFindings("未发现服务器图标", a.Findings, 6, "server",
		func(f IconFinding) string { return f.File },
		func(f IconFinding) string { return f.Reason })
}
