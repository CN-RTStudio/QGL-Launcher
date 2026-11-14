package main

func (a *AntiXrayAudit) Describe() string {
	return describeFileReason("反矿透配置未发现风险", a.Findings, 12)
}
func saxLoadText(a *AntiXrayAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func saxBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}
