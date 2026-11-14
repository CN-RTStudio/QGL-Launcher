package main

import ()

func (a *LevelDataAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *LevelDataAudit) Describe() string {
	return describeReasonDetail("level.dat 未发现风险", a.Findings, 12)
}
