package main

const (
	swsMaxFindings     = 32
	swsMaxProps        = 256 * 1024
	swsMaxPlayers      = 500
	swsMaxViewDistance = 16
	swsReasonMissing   = "missing"
	swsReasonSymlink   = "symlink"
	swsReasonTooLarge  = "too-large"
	swsReasonUnread    = "unreadable"
	swsReasonSeed      = "world-seed-exposed"
	swsReasonSeedBad   = "world-seed-invalid"
	swsReasonPlayers   = "max-players-invalid"
	swsReasonView      = "view-distance-too-large"
	swsReasonSim       = "simulation-distance-too-large"
)

type WorldSeedFinding = auditFinding

type WorldSeedAudit struct {
	ServerDir string
	Findings  []WorldSeedFinding
}

func (a *WorldSeedAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swsMaxFindings, WorldSeedFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldSeedAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldSeedFinding) bool { return f.Blocking })
}

func (a *WorldSeedAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldSeedAudit) Describe() string {
	return describeFileReasonDetail("世界种子与容量配置未发现风险", a.Findings, 12)
}
