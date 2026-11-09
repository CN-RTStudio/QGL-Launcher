package main

import (
	"fmt"
	"sort"
	"strings"
)

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
