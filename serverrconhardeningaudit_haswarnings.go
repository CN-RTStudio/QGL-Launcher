package main

func (a *RconHardeningAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *RconHardeningAudit) Describe() string {
	return describeAuditFindings("RCON 配置未发现风险", a.Findings, 10,
		func(f RconHardeningFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f RconHardeningFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
