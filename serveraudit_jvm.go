package main

import (
	"time"
)

const (
	crReasonOK            = "ok"
	crReasonMissing       = "missing"
	crReasonUnreadable    = "unreadable"
	crReasonSymlink       = "symlink"
	crReasonTooLarge      = "too-large"
	crReasonTooMany       = "too-many"
	crReasonBadName       = "bad-name"
	crReasonSecret        = "secret-leak"
	crReasonHomePath      = "home-path-leak"
	crReasonStale         = "stale-report"
	crReasonWorldWritable = "world-writable"

	crMaxFileBytes = 8 << 20
	crMaxFiles     = 128
	crMaxFindings  = 64
	crScanBytes    = 256 << 10
	crStaleAfter   = 30 * 24 * time.Hour
)

func (a CrashReportAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportFinding) bool { return f.Blocking })
}

func (a CrashReportAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f CrashReportFinding) bool { return !f.Blocking && f.Reason != crReasonOK })
}
