package main

const (
	sbcMaxFindings       = 36
	sbcMaxConfig         = 256 * 1024
	sbcReasonOK          = "ok"
	sbcReasonMissing     = "missing"
	sbcReasonSymlink     = "symlink"
	sbcReasonTooLarge    = "too-large"
	sbcReasonUnread      = "unreadable"
	sbcReasonEmpty       = "empty-config"
	sbcReasonThrottle    = "connection-throttle-disabled"
	sbcReasonThrottleBad = "connection-throttle-invalid"
	sbcReasonPath        = "path-escape"
	sbcReasonControl     = "control-characters"
	sbcReasonProfiling   = "plugin-profiling-enabled"
	sbcReasonSpawn       = "spawn-limit-too-high"
	sbcReasonChunkGC     = "chunk-gc-disabled"
)

type BukkitFinding = auditFinding
type BukkitAudit struct {
	ServerDir string
	Findings  []BukkitFinding
}

func (a *BukkitAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbcMaxFindings, BukkitFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BukkitAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BukkitFinding) bool { return f.Blocking })
}
