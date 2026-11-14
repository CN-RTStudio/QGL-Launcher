package main

import ()

func (a PlayerPrivacyAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PlayerPrivacyFinding) bool { return f.Blocking })
}
func (a PlayerPrivacyAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PlayerPrivacyFinding) bool { return !f.Blocking && f.Reason != ppReasonOK })
}

func (a PlayerPrivacyAudit) Describe() string {
	return describeTaggedFindings("玩家身份数据未发现风险", a.Findings, ppReasonOK, "player-data", ppMaxFindings,
		func(f PlayerPrivacyFinding) string { return f.Reason },
		func(f PlayerPrivacyFinding) string { return f.Source },
		func(f PlayerPrivacyFinding) string { return f.Detail })
}

func (a *PlayerPrivacyAudit) add(source, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ppMaxFindings, PlayerPrivacyFinding{Source: source, Reason: reason, Detail: detail, Blocking: blocking})
}
