package main

func (a PlayerPrivacyAudit) Describe() string {
	return describeTaggedFindings("玩家身份数据未发现风险", a.Findings, ppReasonOK, "player-data", ppMaxFindings,
		func(f PlayerPrivacyFinding) string { return f.Reason },
		func(f PlayerPrivacyFinding) string { return f.Source },
		func(f PlayerPrivacyFinding) string { return f.Detail })
}

func (a *PlayerPrivacyAudit) add(source, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ppMaxFindings, PlayerPrivacyFinding{Source: source, Reason: reason, Detail: detail, Blocking: blocking})
}
