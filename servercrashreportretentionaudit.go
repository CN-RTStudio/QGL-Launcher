package main

const (
	scgMaxFindings  = 24
	scgMaxReports   = 200
	scgMaxReport    = 64 * 1024
	scgMaxTotalSize = 512 * 1024 * 1024
	scgReasonMiss   = "missing-dir"
	scgReasonLink   = "symlink-dir"
	scgReasonRead   = "unreadable"
	scgReasonMany   = "too-many-reports"
	scgReasonBig    = "report-too-large"
	scgReasonTotal  = "total-size"
	scgReasonName   = "odd-report-name"
	scgReasonSeed   = "seed-in-report"
	scgReasonToken  = "secret-in-report"
)

type CrashReportHygieneFinding = auditFinding

type CrashReportHygieneAudit struct {
	ServerDir string
	Findings  []CrashReportHygieneFinding
}

func (a *CrashReportHygieneAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, scgMaxFindings, CrashReportHygieneFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *CrashReportHygieneAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportHygieneFinding) bool { return f.Blocking })
}

func (a *CrashReportHygieneAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *CrashReportHygieneAudit) Describe() string {
	return describeReasonDetail("crash-reports 未发现风险", a.Findings, 12)
}

var scgSecretMarkers = []string{"session-token", "accessToken", "rcon.password=", "Authorization: Bearer"}
