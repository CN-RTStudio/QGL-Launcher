package main

func (a *PregenAudit) Describe() string {
	return describeFileReason("区块预生成配置未发现风险", a.Findings, 12)
}

func spgLoadText(a *PregenAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spgText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}
