package main

import (
	"regexp"
	"time"
)

const (
	sbpMaxFindings  = 32
	sbpMaxFile      = 512 * 1024
	sbpMaxEntries   = 2000
	sbpReasonMiss   = "missing"
	sbpReasonLink   = "symlink"
	sbpReasonLarge  = "too-large"
	sbpReasonRead   = "unreadable"
	sbpReasonShape  = "invalid-shape"
	sbpReasonLargeN = "too-many-entries"
	sbpReasonUUID   = "invalid-uuid"
	sbpReasonName   = "invalid-name"
	sbpReasonTime   = "invalid-timestamp"
	sbpReasonReason = "unsafe-reason"
	sbpReasonDup    = "duplicate-uuid"
	sbpReasonPerm   = "many-permanent-bans"
)

type BannedPlayerFinding = auditFinding

type BannedPlayerAudit struct {
	ServerDir string
	Findings  []BannedPlayerFinding
}

func (a *BannedPlayerAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbpMaxFindings, BannedPlayerFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BannedPlayerAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BannedPlayerFinding) bool { return f.Blocking })
}

func (a *BannedPlayerAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BannedPlayerAudit) Describe() string {
	return describeReasonDetail("banned-players.json 未发现风险", a.Findings, 12)
}

type sbpEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
}

var sbpUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var sbpNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)

func sbpParseTime(value string) bool {
	if value == "" || value == "forever" || value == "infinite" {
		return true
	}
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05 -0700"}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, value); err == nil {
			return true
		}
	}
	return false
}
