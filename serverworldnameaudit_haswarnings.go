package main

import ()

func (a *WorldNameAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldNameAudit) Describe() string {
	return describeFileReasonDetail("世界目录配置未发现风险", a.Findings, 12)
}
