package main

import "time"

const (
	bkReasonOK            = "ok"
	bkReasonMissing       = "missing"
	bkReasonUnreadable    = "unreadable"
	bkReasonTooLarge      = "too-large"
	bkReasonSymlink       = "symlink"
	bkReasonTooMany       = "too-many"
	bkReasonEmptyBackup   = "empty-backup"
	bkReasonStaleBackup   = "stale-backup"
	bkReasonWorldWritable = "world-writable"
	bkReasonBadName       = "bad-name"
	bkReasonDuplicate     = "duplicate-name"

	bkMaxFileBytes  = 2 << 30
	bkMaxEntries    = 64
	bkMaxFindings   = 64
	bkStaleAfter    = 7 * 24 * time.Hour
	bkMinBackupSize = 4 << 10
)

var bkExts = []string{".zip", ".tar", ".tgz", ".tar.gz", ".7z", ".gz", ".zst"}

type BackupFinding = auditFinding
type BackupAudit struct {
	Dir      string
	Now      time.Time
	Backups  []string
	Findings []BackupFinding
}

func (a BackupAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BackupFinding) bool { return f.Blocking })
}
func (a BackupAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f BackupFinding) bool { return !f.Blocking && f.Reason != bkReasonOK })
}
func (a BackupAudit) Codes() []string {
	return findingCodesSkip(a.Findings, bkReasonOK, func(f BackupFinding) string { return f.Reason })
}
