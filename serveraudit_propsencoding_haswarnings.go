package main

import ()

func (a *PropertiesEncodingAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PropertiesEncodingAudit) Describe() string {
	return describeReasonDetail("server.properties 编码未发现风险", a.Findings, 12)
}
