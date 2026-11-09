package main

const (
	fkReasonOK              = "ok"
	fkReasonMissing         = "missing-all"
	fkReasonSymlink         = "symlink"
	fkReasonTooLarge        = "too-large"
	fkReasonWorldWritable   = "world-writable"
	fkReasonUnreadable      = "unreadable"
	fkReasonThrottleOff     = "connection-throttle-off"
	fkReasonLegacyProxy     = "legacy-proxy-enabled"
	fkReasonProxySecret     = "proxy-secret-missing"
	fkReasonXrayOff         = "anti-xray-off"
	fkReasonPacketLimiter   = "packet-limiter-off"
	fkReasonPacketRate      = "max-packet-rate-high"
	fkReasonCollisions      = "max-entity-collisions-high"
	fkReasonActivationRange = "activation-range-high"
	fkReasonViewDistance    = "view-distance-high"
	fkReasonSaveInterval    = "autosave-interval-high"
	fkReasonIdleTimeout     = "idle-timeout-zero"
	fkReasonUnknownValue    = "non-numeric-value"

	fkMaxConfigBytes = 2 << 20
	fkMaxFindings    = 48
)

var fkConfigFiles = []string{
	"bukkit.yml",
	"spigot.yml",
	"paper.yml",
	"config/paper-global.yml",
	"config/paper-world-defaults.yml",
}

type ForkConfigFinding = auditFinding

type ForkConfigAudit struct {
	Dir      string
	Files    []string
	Findings []ForkConfigFinding
}

func (a ForkConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ForkConfigFinding) bool { return f.Blocking })
}

func (a ForkConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ForkConfigFinding) bool { return !f.Blocking && f.Reason != fkReasonOK })
}
