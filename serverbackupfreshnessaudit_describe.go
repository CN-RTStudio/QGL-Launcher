package main

import (
	"fmt"
)

func (a BackupAudit) Describe() string {
	return describeLabeledFindings("未发现备份", a.Findings, 4, "",
		func(f BackupFinding) string { return f.File },
		func(f BackupFinding) string { return f.Reason })
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
