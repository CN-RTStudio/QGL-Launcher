package main

const (
	sptMaxFindings   = 36
	sptMaxFile       = 256 * 1024
	sptReasonMiss    = "missing"
	sptReasonLink    = "symlink"
	sptReasonLarge   = "too-large"
	sptReasonRead    = "unreadable"
	sptReasonEmpty   = "empty-config"
	sptReasonBungee  = "bungeecord-trust"
	sptReasonScript  = "restart-script"
	sptReasonMsg     = "unsafe-message"
	sptReasonTimeout = "timeout-too-long"
	sptReasonTNT     = "tnt-budget-too-high"
	sptReasonRange   = "activation-range-too-high"
	sptReasonRate    = "tick-rate-disabled"
	sptReasonMerge   = "merge-radius-invalid"
	sptReasonSaving  = "world-saving-disabled"
)

type SpigotFinding = auditFinding

type SpigotAudit struct {
	ServerDir string
	Findings  []SpigotFinding
}

func (a *SpigotAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sptMaxFindings, SpigotFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *SpigotAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f SpigotFinding) bool { return f.Blocking })
}
