package main

func (a *ProxyAuthAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *ProxyAuthAudit) Describe() string {
	return describeFileReason("代理转发配置未发现风险", a.Findings, 12)
}

func spaLoadText(a *ProxyAuthAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spaBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}

func spaText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}

func spaSecretProblem(secret string) string {
	if cfgHasControlChars(secret) {
		return spaReasonSecretBad
	}
	if cfgIsPlaceholder(secret) {
		return spaReasonNoSecret
	}
	if len(secret) < spaMinSecretLength {
		return spaReasonWeak
	}
	return ""
}
