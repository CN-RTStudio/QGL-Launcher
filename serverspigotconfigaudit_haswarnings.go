package main

func (a *SpigotAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *SpigotAudit) Describe() string {
	return describeFileReasonDetail("Spigot 服务端配置未发现风险", a.Findings, 12)
}
