package main

import ()

func (a CommandAliasAudit) Describe() string {
	return describeTaggedFindings("服务器命令别名未发现异常", a.Findings, caReasonOK, "", caMaxFindings,
		func(f CommandAliasFinding) string { return f.Reason },
		func(f CommandAliasFinding) string { return f.File },
		func(f CommandAliasFinding) string { return f.Detail })
}

func (a *CommandAliasAudit) add(file, alias, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, caMaxFindings, CommandAliasFinding{File: file, Alias: alias, Reason: reason, Detail: detail, Blocking: blocking})
}
