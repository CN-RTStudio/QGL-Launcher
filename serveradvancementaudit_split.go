package main

import (
	"fmt"
	"sort"
	"strings"
)

type AdvancementAudit struct {
	Dir      string
	Findings []AdvancementFinding
	Files    int
}

func (a AdvancementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AdvancementFinding) bool { return f.Blocking })
}

func (a AdvancementAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f AdvancementFinding) bool { return !f.Blocking && f.Reason != adReasonOK })
}

func (a AdvancementAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == adReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.Dir, f.Reason, f.Detail))
		if len(parts) >= adMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器进度数据未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *AdvancementAudit) add(dir, file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, adMaxFindings, AdvancementFinding{Dir: dir, File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func adJSONDepth(data []byte) int {
	return jsonMaxDepth(data)
}

func adDuplicateKeys(data []byte) []string {
	return jsonDuplicateKeys(data)
}
