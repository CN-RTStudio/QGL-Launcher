package main

import (
	"fmt"
	"sort"
	"strings"
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

var crSecretPatterns = []string{
	"password=",
	"password:",
	"rcon.password",
	"rcon-password",
	"access_token",
	"authorization: bearer",
	"api_key",
	"apikey",
	"secret_key",
	"private_key",
	"-----begin",
	"sessionid=",
	"session_id=",
	"jdbc:mysql://",
	"mongodb://",
	"postgres://",
}

var crHomePatterns = []string{
	"/home/",
	"/root/",
	"c:\\users\\",
	"/users/",
}

type CrashReportFinding = auditFinding

type CrashReportAudit struct {
	Dir      string
	Files    []string
	Findings []CrashReportFinding
}

func (a CrashReportAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f CrashReportFinding) bool { return f.Blocking })
}

func (a CrashReportAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f CrashReportFinding) bool { return !f.Blocking && f.Reason != crReasonOK })
}

func (a CrashReportAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == crReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "crash-reports"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= crMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "崩溃报告未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *CrashReportAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, crMaxFindings, CrashReportFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func crScanBody(audit *CrashReportAudit, rel, body string) {
	lower := strings.ToLower(body)
	for _, pattern := range crSecretPatterns {
		idx := strings.Index(lower, pattern)
		if idx < 0 {
			continue
		}
		snippet := crRedactContext(lower[idx : idx+len(pattern)])
		audit.add(rel, crReasonSecret, fmt.Sprintf("疑似明文凭据: %s", snippet), true)
		break
	}
	for _, pattern := range crHomePatterns {
		if strings.Contains(lower, pattern) {
			audit.add(rel, crReasonHomePath, "报告包含用户主目录绝对路径", false)
			break
		}
	}
}
