package main

func (a *BukkitAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BukkitAudit) Describe() string {
	return describeFileReasonDetail("Bukkit 配置未发现风险", a.Findings, 12)
}
