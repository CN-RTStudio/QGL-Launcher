package main

type YamlHazardFinding = auditFinding

type YamlHazardAudit struct {
	Dir      string
	Files    []string
	Findings []YamlHazardFinding
}

func (a YamlHazardAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f YamlHazardFinding) bool { return f.Blocking })
}

func (a YamlHazardAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f YamlHazardFinding) bool { return !f.Blocking && f.Reason != yhReasonOK })
}

func (a YamlHazardAudit) Describe() string {
	return describeTaggedFindings("YAML 配置未发现构造风险", a.Findings, yhReasonOK, "yaml", yhMaxFindings,
		func(f YamlHazardFinding) string { return f.Reason },
		func(f YamlHazardFinding) string { return f.File },
		func(f YamlHazardFinding) string { return f.Detail })
}

func (a *YamlHazardAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, yhMaxFindings, YamlHazardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
