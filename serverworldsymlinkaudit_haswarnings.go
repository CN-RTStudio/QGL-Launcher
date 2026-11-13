package main

func (a *WorldSymlinkAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldSymlinkAudit) Describe() string {
	return describeAuditFindings("世界存档目录未发现符号链接风险", a.Findings, 12,
		func(f WorldSymlinkFinding) []string {
			return []string{f.Reason, f.Path}
		},
		func(f WorldSymlinkFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
