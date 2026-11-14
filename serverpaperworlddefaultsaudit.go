package main

import ()

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
