package main

import (
	"path/filepath"
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
