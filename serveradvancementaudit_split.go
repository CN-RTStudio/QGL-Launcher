package main

type AdvancementAudit struct {
	Dir      string
	Findings []AdvancementFinding
	Files    int
}

func (a AdvancementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AdvancementFinding) bool { return f.Blocking })
}

func (a AdvancementAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f AdvancementFinding) bool { return !f.Blocking && f.Reason != adReasonOK })
}

func (a AdvancementAudit) Describe() string {
	return describeTaggedFindings("服务器进度数据未发现异常", a.Findings, adReasonOK, "", adMaxFindings,
		func(f AdvancementFinding) string { return f.Reason },
		func(f AdvancementFinding) string { return f.Dir },
		func(f AdvancementFinding) string { return f.Detail })
}

func (a *AdvancementAudit) add(dir, file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, adMaxFindings, AdvancementFinding{Dir: dir, File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func adJSONDepth(data []byte) int {
	return jsonMaxDepth(data)
}

func adDuplicateKeys(data []byte) []string {
	return jsonDuplicateKeys(data)
}
