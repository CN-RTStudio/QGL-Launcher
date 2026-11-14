package main

import ()

func (a *DynmapAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *DynmapAudit) Describe() string {
	return describeFileReason("网页地图配置未发现风险", a.Findings, 12)
}

func spdLoadText(a *DynmapAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}
