package main

type JMXAudit struct {
	Dir      string
	Sources  []string
	Findings []JMXFinding
}

func (a JMXAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JMXFinding) bool { return f.Blocking })
}

func (a JMXAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JMXFinding) bool { return !f.Blocking && f.Reason != jmxReasonOK })
}

func (a JMXAudit) Codes() []string {
	return findingCodesSkip(a.Findings, jmxReasonOK, func(f JMXFinding) string { return f.Reason })
}

func (a JMXAudit) Describe() string {
	return describeLabeledFindings("未发现 JMX 远程管理配置", a.Findings, 6, "server",
		func(f JMXFinding) string { return f.File },
		func(f JMXFinding) string { return f.Reason })
}
