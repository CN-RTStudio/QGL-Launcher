package main

import (
	"fmt"
	"strings"
)

func (a BanListAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现封禁名单"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a BanListAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f BanFinding) bool { return f.Blocking }, func(f BanFinding) bool { return !f.Blocking && f.Reason != banReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *BanListAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, banMaxFindings, BanFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
