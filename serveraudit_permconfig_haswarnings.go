package main

func (a *PermissionsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *PermissionsAudit) Describe() string {
	return describeReasonDetail("permissions.yml 未发现风险", a.Findings, 12)
}

type smnEntry struct {
	Path  string
	Value string
}
