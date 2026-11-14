package main

import ()

func (a *UnsafeToggleAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *UnsafeToggleAudit) Describe() string {
	return describeFileReason("实验性开关未发现风险", a.Findings, 12)
}

func sunLoadText(a *UnsafeToggleAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}
