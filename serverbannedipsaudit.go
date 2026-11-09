package main

import (
	"net"
	"strings"
)

const (
	sbiMaxFindings    = 36
	sbiMaxFile        = 512 * 1024
	sbiMaxEntries     = 2048
	sbiReasonMissing  = "missing"
	sbiReasonSymlink  = "symlink"
	sbiReasonTooLarge = "too-large"
	sbiReasonUnread   = "unreadable"
	sbiReasonParse    = "invalid-json"
	sbiReasonCount    = "too-many-entries"
	sbiReasonAddress  = "invalid-address"
	sbiReasonDup      = "duplicate-address"
	sbiReasonExpiry   = "invalid-expiry"
)

type BannedIPEntry struct {
	IP      string `json:"ip"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
}

type BannedIPFinding = auditFinding

type BannedIPAudit struct {
	ServerDir string
	Findings  []BannedIPFinding
}

func (a *BannedIPAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbiMaxFindings, BannedIPFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BannedIPAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BannedIPFinding) bool { return f.Blocking })
}

func (a *BannedIPAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BannedIPAudit) Describe() string {
	return describeFileReasonDetail("IP 封禁清单未发现风险", a.Findings, 12)
}

func sbiValidAddress(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	if net.ParseIP(trimmed) != nil {
		return true
	}
	return false
}
