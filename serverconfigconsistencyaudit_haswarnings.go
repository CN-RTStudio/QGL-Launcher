package main

import ()

func (a *ConsistencyAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *ConsistencyAudit) Describe() string {
	return describeReasonDetail("服务端配置组合未发现风险", a.Findings, 12)
}
