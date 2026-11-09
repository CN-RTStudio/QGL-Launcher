package main

const (
	tkReasonOK              = "ok"
	tkReasonMissing         = "missing"
	tkReasonUnreadable      = "unreadable"
	tkReasonSymlink         = "symlink"
	tkReasonWatchdogOff     = "watchdog-disabled"
	tkReasonTickBudget      = "tick-budget"
	tkReasonUnsafeSave      = "unsafe-save"
	tkReasonPlayerLimit     = "player-limit"
	tkReasonCompression     = "compression-threshold"
	tkReasonViewDistance    = "view-distance"
	tkReasonSimulation      = "simulation-distance"
	tkReasonBroadcast       = "broadcast-range"
	tkReasonCollisions      = "entity-collisions"
	tkReasonIdleTimeout     = "idle-timeout"
	tkReasonSpawnProtection = "spawn-protection"
	tkReasonResourcePack    = "required-resource-pack"
	tkReasonLevelName       = "unsafe-level-name"
	tkReasonStatusOff       = "status-hidden"
	tkReasonTooLarge        = "too-large"

	tkMaxPropertiesBytes = 1 << 20
	tkMaxFindings        = 48
	tkMinTickBudget      = 1000
	tkMaxTickBudget      = 600000
	tkMaxPlayersBudget   = 200
	tkMaxViewDistance    = 16
	tkMaxBroadcast       = 200
	tkMaxCollisions      = 8
)

type TickConfigFinding = auditFinding
type TickConfigAudit struct {
	Dir      string
	File     string
	Props    map[string]string
	Findings []TickConfigFinding
}

func (a TickConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TickConfigFinding) bool { return f.Blocking })
}
func (a TickConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f TickConfigFinding) bool { return !f.Blocking && f.Reason != tkReasonOK })
}
