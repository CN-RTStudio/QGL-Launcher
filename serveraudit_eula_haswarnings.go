package main

import ()

func (a *EulaAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *EulaAudit) Describe() string {
	return describeFileReasonDetail("EULA 协议文件未发现风险", a.Findings, 12)
}
