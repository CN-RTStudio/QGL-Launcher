package main

func (a WorldRegionAudit) Describe() string {
	return describeTaggedFindings("世界区域文件未发现风险", a.Findings, wrReasonOK, "world", wrMaxFindings,
		func(f WorldRegionFinding) string { return f.Reason },
		func(f WorldRegionFinding) string { return f.Path },
		func(f WorldRegionFinding) string { return f.Detail })
}

func (a *WorldRegionAudit) add(path, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, wrMaxFindings, WorldRegionFinding{Path: path, Reason: reason, Detail: detail, Blocking: blocking})
}
