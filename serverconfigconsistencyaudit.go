package main

import ()

const (
	sccMaxFindings     = 28
	sccMaxFile         = 512 * 1024
	sccReasonMiss      = "missing"
	sccReasonRead      = "unreadable"
	sccReasonOnline    = "online-mode-off"
	sccReasonWhitelist = "whitelist-off-with-permissive"
	sccReasonRconPass  = "rcon-password-weak"
	sccReasonRconOpen  = "rcon-exposed"
	sccReasonSecure    = "secure-profile-off"
	sccReasonSpawn     = "spawn-protection-off"
	sccReasonDistance  = "view-distance-mismatch"
	sccReasonPlayers   = "max-players-invalid"
	sccReasonOpsMany   = "too-many-operators"
	sccReasonQuery     = "query-enabled"
)

type ConsistencyFinding = auditFinding
type ConsistencyAudit struct {
	ServerDir string
	Findings  []ConsistencyFinding
}

func (a *ConsistencyAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sccMaxFindings, ConsistencyFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *ConsistencyAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ConsistencyFinding) bool { return f.Blocking })
}
