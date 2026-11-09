package main

import "fmt"

const (
	secMaxFindings       = 48
	secMaxYAML           = 512 * 1024
	secDefaultCollisions = 8
	secHardCollisions    = 32
	secMaxActivation     = 48
	secMaxSpawnRange     = 10
	secReasonOK          = "ok"
	secReasonMissing     = "missing"
	secReasonSymlink     = "symlink"
	secReasonTooLarge    = "too-large"
	secReasonUnread      = "unreadable"
	secReasonBadValue    = "bad-value"
	secReasonCramming    = "entity-cramming-disabled"
	secReasonSpawner     = "spawner-nerf-disabled"
	secReasonActivation  = "entity-activation-range-large"
	secReasonSpawnRange  = "mob-spawn-range-large"
	secReasonSaveLimit   = "entity-save-limit-unbounded"
	secReasonPaperLimit  = "paper-entity-save-limit-unbounded"
)

type EntityCrammingFinding = auditFinding
type EntityCrammingAudit struct {
	ServerDir string
	Findings  []EntityCrammingFinding
}

func (a *EntityCrammingAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, secMaxFindings, EntityCrammingFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *EntityCrammingAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f EntityCrammingFinding) bool { return f.Blocking })
}
func (a *EntityCrammingAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f EntityCrammingFinding) bool { return f.Reason != secReasonOK && !f.Blocking })
}
func (a *EntityCrammingAudit) Describe() string {
	return describeFindings(a.Findings, func(f EntityCrammingFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}
func secLoadText(a *EntityCrammingAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}
