package main

const (
	smaMaxFindings     = 40
	smaMaxProps        = 256 * 1024
	smaMaxWorldSize    = 29999984
	smaMinIdleMinutes  = 5
	smaMaxPlayersSoft  = 200
	smaReasonOK        = "ok"
	smaReasonMissing   = "missing"
	smaReasonSymlink   = "symlink"
	smaReasonTooLarge  = "too-large"
	smaReasonUnread    = "unreadable"
	smaReasonBadValue  = "bad-value"
	smaReasonFlight    = "allow-flight-enabled"
	smaReasonIdle      = "idle-timeout-disabled"
	smaReasonSpawnProt = "spawn-protection-disabled"
	smaReasonWorldSize = "max-world-size-invalid"
	smaReasonPlayerCap = "max-players-oversized"
	smaReasonDebug     = "debug-enabled"
)

type MovementGuardFinding = auditFinding
type MovementGuardAudit struct {
	ServerDir string
	Findings  []MovementGuardFinding
}

func (a *MovementGuardAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smaMaxFindings, MovementGuardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *MovementGuardAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f MovementGuardFinding) bool { return f.Blocking })
}

func (a *MovementGuardAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f MovementGuardFinding) bool { return f.Reason != smaReasonOK && !f.Blocking })
}
