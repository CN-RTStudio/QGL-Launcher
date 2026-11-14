package main

import ()

const (
	sldMaxFindings = 24
	sldMaxFile     = 64 * 1024 * 1024
	sldReasonMiss  = "missing"
	sldReasonLink  = "symlink"
	sldReasonLarge = "too-large"
	sldReasonRead  = "unreadable"
	sldReasonMagic = "invalid-gzip"
	sldReasonNBT   = "invalid-nbt"
	sldReasonName  = "unsafe-level-name"
	sldReasonAllow = "commands-allowed"
	sldReasonHard  = "hardcore-world"
	sldReasonSeed  = "seed-embedded"
	sldReasonGen   = "unknown-generator"
)

type LevelDataFinding = auditFinding
type LevelDataAudit struct {
	ServerDir string
	Findings  []LevelDataFinding
}

func (a *LevelDataAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sldMaxFindings, LevelDataFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *LevelDataAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LevelDataFinding) bool { return f.Blocking })
}
