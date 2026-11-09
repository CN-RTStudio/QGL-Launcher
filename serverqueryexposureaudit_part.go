package main

func (a *QueryExposureAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f QueryExposureFinding) bool { return f.Blocking })
}

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

func syqHasControl(text string) bool {
	for _, r := range text {
		if r < 0x20 && r != '\t' {
			return true
		}
		if r == 0x7f {
			return true
		}
		if r >= 0x80 && r <= 0x9f {
			return true
		}
	}
	return false
}
