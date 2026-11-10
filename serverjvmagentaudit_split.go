package main

func (a JVMAgentAudit) Describe() string {
	return describeTaggedFindings("JVM 启动参数未发现代理注入风险", a.Findings, jaReasonOK, "jvm-args", jaMaxFindings,
		func(f JVMAgentFinding) string { return f.Reason },
		func(f JVMAgentFinding) string { return f.File },
		func(f JVMAgentFinding) string { return f.Detail })
}
func (a *JVMAgentAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, jaMaxFindings, JVMAgentFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
