package main

import (
	"fmt"
)

func (a BudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f BudgetFinding) bool { return !f.Blocking && f.Reason != bdReasonOK })
}

func (a BudgetAudit) Describe() string {
	return describeTaggedFindings("服务器磁盘占用未发现异常", a.Findings, bdReasonOK, "", bdMaxFindings,
		func(f BudgetFinding) string { return f.Reason },
		func(f BudgetFinding) string { return f.Area },
		func(f BudgetFinding) string { return f.Detail })
}

func (a *BudgetAudit) add(area, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, bdMaxFindings, BudgetFinding{Area: area, Reason: reason, Detail: detail, Blocking: blocking})
}

func bdHuman(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGT"[exp])
}

type bdWalkState struct {
	bytes     int64
	entries   int
	files     int
	dirs      int
	links     int
	truncated bool
}
