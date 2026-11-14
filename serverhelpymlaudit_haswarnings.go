package main

import ()

func (a *HelpYmlAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *HelpYmlAudit) Describe() string {
	return describeFileReasonDetail("服务器帮助配置未发现风险", a.Findings, 12)
}

func shyHasControlChars(text string) bool {
	return hasControlCharsText(text)
}
