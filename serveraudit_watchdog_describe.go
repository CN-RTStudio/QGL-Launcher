package main

import ()

func (a *WatchdogAudit) Describe() string {
	return describeFileReason("看门狗与重启配置未发现风险", a.Findings, 12)
}

func spwLoadText(a *WatchdogAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spwBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}
