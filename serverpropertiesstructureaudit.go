package main

import (
	"fmt"
)

const (
	spxMaxFindings = 18
	spxMaxFile     = 256 * 1024
	spxMaxKeys     = 512
	spxMaxDetail   = 8
	spxMiss        = "properties-missing"
	spxRead        = "properties-unreadable"
	spxLink        = "properties-symlink"
	spxEmpty       = "properties-empty"
	spxMalformed   = "properties-line-malformed"
	spxDupKey      = "properties-duplicate-key"
	spxCaseDup     = "properties-case-duplicate"
	spxEmptyKey    = "properties-empty-key"
	spxKeySpace    = "properties-key-whitespace"
	spxInlineHash  = "properties-inline-comment"
	spxTooManyKeys = "properties-key-count"
	spxLongValue   = "properties-value-too-long"
)

type PropDupFinding = auditFinding

type PropDupAudit struct {
	ServerDir string
	Findings  []PropDupFinding
}

func (a *PropDupAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spxMaxFindings, PropDupFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PropDupAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PropDupFinding) bool { return f.Blocking })
}

func (a *PropDupAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PropDupAudit) Describe() string {
	return describeReasonDetail("属性文件键结构未发现重复或畸形", a.Findings, 12)
}

func spxEntry(index int, key, value string) string {
	if len(value) > 40 {
		value = value[:40] + "…"
	}
	return fmt.Sprintf("第 %d 行 %s=%s", index, key, value)
}
