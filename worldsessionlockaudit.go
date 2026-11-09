package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const (
	wslReasonOK            = "ok"
	wslReasonMissing       = "missing"
	wslReasonNotDirectory  = "not-directory"
	wslReasonSymlink       = "symlink"
	wslReasonUnreadable    = "unreadable"
	wslReasonTooLarge      = "too-large"
	wslReasonBadLevelDat   = "bad-level-dat"
	wslReasonWorldInUse    = "world-in-use"
	wslReasonLockStale     = "lock-stale"
	wslReasonWorldReadable = "world-readable"
	wslReasonMissingLock   = "missing-lock"

	wslMaxLevelDatBytes = 16 << 20
	wslInUseWindow      = 30 * time.Minute
	wslStaleLockWindow  = 90 * 24 * time.Hour
	wslMaxWorlds        = 8
	wslMaxFindings      = 48
)

var wslWorldCandidates = []string{
	"world",
	"world_nether",
	"world_the_end",
	filepath.Join("world", "DIM-1"),
	filepath.Join("world", "DIM1"),
}

type SessionLockFinding struct {
	World    string
	Reason   string
	Detail   string
	Blocking bool
}

type SessionLockAudit struct {
	Dir      string
	Now      time.Time
	Worlds   []string
	Findings []SessionLockFinding
}

func (a SessionLockAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f SessionLockFinding) bool { return f.Blocking })
}

func (a SessionLockAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f SessionLockFinding) bool { return !f.Blocking && f.Reason != wslReasonOK })
}

func (a SessionLockAudit) Codes() []string {
	return findingCodesSkip(a.Findings, wslReasonOK, func(f SessionLockFinding) string { return f.Reason })
}

func (a SessionLockAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现世界目录"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.World, f.Reason))
		if len(parts) >= 4 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a SessionLockAudit) Summary() string {
	blocking, warnings := 0, 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != wslReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("worlds=%d findings=%d blocking=%d warnings=%d", len(a.Worlds), len(a.Findings), blocking, warnings)
}

func (a *SessionLockAudit) add(world, reason, detail string, blocking bool) {
	if len(a.Findings) >= wslMaxFindings {
		return
	}
	a.Findings = append(a.Findings, SessionLockFinding{World: world, Reason: reason, Detail: detail, Blocking: blocking})
}
