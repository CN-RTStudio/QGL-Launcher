package main

import (
	"fmt"
	"sort"
	"strings"
)

func (a BudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f BudgetFinding) bool { return !f.Blocking && f.Reason != bdReasonOK })
}

func (a BudgetAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == bdReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.Area, f.Reason, f.Detail))
		if len(parts) >= bdMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器磁盘占用未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
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
