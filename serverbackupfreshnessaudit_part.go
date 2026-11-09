package main

import (
	"fmt"
	"strings"
)

func (a BackupAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现备份"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.File, f.Reason))
		if len(parts) >= 4 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a BackupAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f BackupFinding) bool { return f.Blocking }, func(f BackupFinding) bool { return !f.Blocking && f.Reason != bkReasonOK })
	newest := "none"
	if len(a.Backups) > 0 {
		newest = a.Backups[0]
	}
	return fmt.Sprintf("backups=%d findings=%d blocking=%d warnings=%d newest=%s", len(a.Backups), len(a.Findings), blocking, warnings, newest)
}

func (a *BackupAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, bkMaxFindings, BackupFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func bkNameSane(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x20 || ch == 0x7f {
			return false
		}
	}
	if strings.Contains(name, "..") {
		return false
	}
	return true
}
