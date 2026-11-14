package main

import ()

func (a *PaperAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PaperAudit) Describe() string {
	return describeFileReasonDetail("Paper 全局配置未发现风险", a.Findings, 12)
}

func pacHasControlChars(text string) bool {
	return hasControlCharsText(text)
}
