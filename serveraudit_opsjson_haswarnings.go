package main

import ()

func (a *OpsJsonAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsJsonAudit) Describe() string {
	return describeFileReasonDetail("服务器操作员清单未发现风险", a.Findings, 12)
}
