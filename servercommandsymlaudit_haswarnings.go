package main

func (a *CommandsYmlAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *CommandsYmlAudit) Describe() string {
	return describeFileReasonDetail("服务器命令别名配置未发现风险", a.Findings, 12)
}

func scyValidAliasName(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	if value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, c := range value {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
