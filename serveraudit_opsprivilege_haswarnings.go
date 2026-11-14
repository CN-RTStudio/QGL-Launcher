package main

import ()

func (a *OpsPrivilegeAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsPrivilegeAudit) Describe() string {
	return describeAuditFindings("运维权限配置未发现风险", a.Findings, 10,
		func(f OpsPrivilegeFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f OpsPrivilegeFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}
