package main

import "fmt"

const (
	cfdMaxFindings      = 48
	cfdMaxProps         = 256 * 1024
	cfdMaxYAML          = 512 * 1024
	cfdThrottleMin      = 1
	cfdThrottleMax      = 10000
	cfdTimeoutMax       = 600
	cfdJoinBurstMax     = 10
	cfdMaxPlayersMax    = 200
	cfdReasonOK         = "ok"
	cfdReasonMissing    = "missing"
	cfdReasonSymlink    = "symlink"
	cfdReasonTooLarge   = "too-large"
	cfdReasonUnreadable = "unreadable"
	cfdReasonBadConfig  = "bad-config"
	cfdReasonBadValue   = "bad-value"
	cfdThrottleOff      = "throttle-disabled"
	cfdThrottleLoose    = "throttle-loose"
	cfdTimeoutLoose     = "slow-timeout"
	cfdJoinBurst        = "join-burst"
	cfdPlayersBulk      = "max-players-large"
	cfdRateLimitOff     = "rate-limit-disabled"
	cfdConflict         = "duplicate-setting"
)

type ConnectionFloodFinding = auditFinding
type ConnectionFloodAudit struct {
	ServerDir string
	Findings  []ConnectionFloodFinding
}

func (a *ConnectionFloodAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, cfdMaxFindings, ConnectionFloodFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *ConnectionFloodAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ConnectionFloodFinding) bool { return f.Blocking })
}
func (a *ConnectionFloodAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ConnectionFloodFinding) bool { return f.Reason != cfdReasonOK && !f.Blocking })
}
func (a *ConnectionFloodAudit) Describe() string {
	return describeFindings(a.Findings, func(f ConnectionFloodFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}
func cfdLoad(a *ConnectionFloodAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}
