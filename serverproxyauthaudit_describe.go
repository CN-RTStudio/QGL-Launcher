package main

func (a *ProxyAuthAudit) Describe() string {
	return describeFileReason("代理转发配置未发现风险", a.Findings, 12)
}

func spaLoadText(a *ProxyAuthAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spaBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}
