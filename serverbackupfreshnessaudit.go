package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

func bkIsArchive(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range bkExts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func auditServerBackupsAt(serverDir string, now time.Time) BackupAudit {
	audit := BackupAudit{Dir: serverDir, Now: now}
	root := filepath.Join(serverDir, "backups")
	entries, err := os.ReadDir(root)
	if err != nil {
		audit.add("backups", bkReasonMissing, "未发现 backups 目录", false)
		audit.add("", bkReasonOK, "无备份归档", false)
		return audit
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		rel := filepath.Join("backups", entry.Name())
		if !entry.IsDir() && !bkIsArchive(entry.Name()) {
			continue
		}
		if !bkNameSane(entry.Name()) {
			audit.add(rel, bkReasonBadName, "备份名含控制字符或路径片段", true)
			continue
		}
		lower := strings.ToLower(entry.Name())
		if seen[lower] {
			audit.add(rel, bkReasonDuplicate, "备份名重复", false)
			continue
		}
		seen[lower] = true
		if len(audit.Backups) >= bkMaxEntries {
			audit.add(rel, bkReasonTooMany, "备份数量超过预算", true)
			break
		}
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil {
			audit.add(rel, bkReasonUnreadable, "备份不可访问", true)
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(rel, bkReasonSymlink, "备份是符号链接", true)
			continue
		}
		if info.IsDir() {
			audit.Backups = append(audit.Backups, rel)
			if info.ModTime().Before(now.Add(-bkStaleAfter)) {
				audit.add(rel, bkReasonStaleBackup, "目录备份超过保留窗口未更新", false)
			}
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(rel, bkReasonUnreadable, "备份不是普通文件", true)
			continue
		}
		if info.Size() > bkMaxFileBytes {
			audit.add(rel, bkReasonTooLarge, "备份超过体积预算", true)
			continue
		}
		if info.Size() < bkMinBackupSize {
			audit.add(rel, bkReasonEmptyBackup, "备份体积异常小", false)
		}
		if info.Mode().Perm()&0o022 != 0 {
			audit.add(rel, bkReasonWorldWritable, "备份对其他用户可写", false)
		}
		if info.ModTime().Before(now.Add(-bkStaleAfter)) {
			audit.add(rel, bkReasonStaleBackup, "备份超过保留窗口未更新", false)
		}
		audit.Backups = append(audit.Backups, rel)
	}
	sort.Slice(audit.Backups, func(i, j int) bool { return audit.Backups[i] > audit.Backups[j] })
	if len(audit.Findings) == 0 {
		audit.add("", bkReasonOK, "备份状态正常", false)
	}
	return audit
}

func AuditServerBackups(serverDir string) BackupAudit {
	return auditServerBackupsAt(serverDir, time.Now())
}
