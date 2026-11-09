package main

import (
	"fmt"
	"strings"
)

func (a WhitelistAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现白名单与操作员配置"
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

func (a WhitelistAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f WhitelistFinding) bool { return f.Blocking }, func(f WhitelistFinding) bool { return !f.Blocking && f.Reason != wlReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *WhitelistAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, wlMaxFindings, WhitelistFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func wlIsCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		ch := value[i]
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') && !(ch >= 'A' && ch <= 'F') {
				return false
			}
		}
	}
	return true
}
