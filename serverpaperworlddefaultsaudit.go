package main

const (
	swdMaxFindings = 32
	swdMaxFile     = 256 * 1024
	swdReasonMiss  = "missing"
	swdReasonLink  = "symlink"
	swdReasonLarge = "too-large"
	swdReasonRead  = "unreadable"
	swdReasonEmpty = "empty-config"
	swdReasonXray  = "anti-xray-disabled"
	swdReasonColl  = "collision-limit"
	swdReasonRate  = "tick-rate-zero"
	swdReasonSave  = "autosave-zero"
	swdReasonRange = "despawn-range-invalid"
	swdReasonScan  = "hopper-scan-high"
	swdReasonChunk = "chunk-unload-disabled"
	swdReasonAlt   = "height-limit-high"
)

type PaperWorldFinding = auditFinding

type PaperWorldAudit struct {
	ServerDir string
	Findings  []PaperWorldFinding
}

func (a *PaperWorldAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swdMaxFindings, PaperWorldFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PaperWorldAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PaperWorldFinding) bool { return f.Blocking })
}

func (a *PaperWorldAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PaperWorldAudit) Describe() string {
	return describeReasonDetail("paper-world-defaults.yml 未发现风险", a.Findings, 12)
}
