package main

import (
	"bytes"
)

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

func (a *LevelDataAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *LevelDataAudit) Describe() string {
	return describeReasonDetail("level.dat 未发现风险", a.Findings, 12)
}

func sldPrintableString(data []byte, tag string) string {
	idx := bytes.Index(data, []byte(tag))
	if idx < 0 || idx+len(tag)+4 > len(data) {
		return ""
	}
	rest := data[idx+len(tag):]
	if rest[0] != 0x08 {
		return ""
	}
	valueLen := int(rest[1])<<8 | int(rest[2])
	if valueLen <= 0 || valueLen > 128 || 3+valueLen > len(rest) {
		return ""
	}
	return string(rest[3 : 3+valueLen])
}
