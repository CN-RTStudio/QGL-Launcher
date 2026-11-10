package main

func (a HelpOverrideAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f HelpOverrideFinding) bool { return !f.Blocking && f.Reason != hoReasonOK })
}

func (a HelpOverrideAudit) Describe() string {
	return describeTaggedFindings("服务器帮助覆盖未发现异常", a.Findings, hoReasonOK, "", hoMaxFindings,
		func(f HelpOverrideFinding) string { return f.Reason },
		func(f HelpOverrideFinding) string { return f.File },
		func(f HelpOverrideFinding) string { return f.Detail })
}

func (a *HelpOverrideAudit) add(file, topic, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, hoMaxFindings, HelpOverrideFinding{File: file, Topic: topic, Reason: reason, Detail: detail, Blocking: blocking})
}
