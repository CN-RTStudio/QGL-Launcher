package main

func (a PluginJarAudit) Describe() string {
	return describeTaggedFindings("插件包结构未发现风险", a.Findings, pjReasonOK, "plugins", pjMaxFindings,
		func(f PluginJarFinding) string { return f.Reason },
		func(f PluginJarFinding) string { return f.Jar },
		func(f PluginJarFinding) string { return f.Detail })
}

func (a *PluginJarAudit) add(jar, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pjMaxFindings, PluginJarFinding{Jar: jar, Reason: reason, Detail: detail, Blocking: blocking})
}
