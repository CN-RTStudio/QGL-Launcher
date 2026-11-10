package main

func (a WorldRegionAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f WorldRegionFinding) bool { return !f.Blocking && f.Reason != wrReasonOK })
}
func (a WorldRegionAudit) Describe() string {
	return describeTaggedFindings("世界区域文件未发现风险", a.Findings, wrReasonOK, "world", wrMaxFindings,
		func(f WorldRegionFinding) string { return f.Reason },
		func(f WorldRegionFinding) string { return f.Path },
		func(f WorldRegionFinding) string { return f.Detail })
}
