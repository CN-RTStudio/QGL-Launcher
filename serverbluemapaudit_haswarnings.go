package main

func (a *BlueMapAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BlueMapAudit) Describe() string {
	return describeFileReason("BlueMap 网页地图配置未发现风险", a.Findings, 12)
}

func sbmLoadText(a *BlueMapAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}
