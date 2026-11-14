package main

import (
	"strings"
	"time"
)

func crParseTimestamp(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, "crash-") {
		return time.Time{}, false
	}
	rest := strings.TrimPrefix(name, "crash-")
	if len(rest) < 19 {
		return time.Time{}, false
	}
	layout := "2006-01-02_15.04.05"
	stamp := rest[:19]
	parsed, err := time.ParseInLocation(layout, stamp, time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

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
