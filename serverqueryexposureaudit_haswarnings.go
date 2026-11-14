package main

func (a *QueryExposureAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *QueryExposureAudit) Describe() string {
	return describeAuditFindings("对外暴露相关配置未发现风险", a.Findings, 9,
		func(f QueryExposureFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f QueryExposureFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
