package main

import ()

func (a *CrashReportHygieneAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportHygieneFinding) bool { return f.Blocking })
}

func (a *CrashReportHygieneAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
