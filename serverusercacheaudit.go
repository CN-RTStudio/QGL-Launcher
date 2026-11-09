package main

import (
	"regexp"
)

const (
	sucMaxFindings    = 36
	sucMaxFile        = 512 * 1024
	sucMaxEntries     = 8192
	sucReasonOK       = "ok"
	sucReasonMissing  = "missing"
	sucReasonSymlink  = "symlink"
	sucReasonTooLarge = "too-large"
	sucReasonUnread   = "unreadable"
	sucReasonParse    = "invalid-json"
	sucReasonShape    = "invalid-shape"
	sucReasonCount    = "too-many-entries"
	sucReasonUUID     = "invalid-uuid"
	sucReasonName     = "invalid-name"
	sucReasonDup      = "duplicate-uuid"
	sucReasonExpiry   = "invalid-expiry"
)

var sucUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var sucNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{3,16}$`)

type UserCacheEntry struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	ExpiresOn string `json:"expiresOn"`
}

type UserCacheFinding = auditFinding

type UserCacheAudit struct {
	ServerDir string
	Findings  []UserCacheFinding
}

func (a *UserCacheAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sucMaxFindings, UserCacheFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *UserCacheAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f UserCacheFinding) bool { return f.Blocking })
}

func (a *UserCacheAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *UserCacheAudit) Describe() string {
	return describeFileReasonDetail("玩家缓存未发现风险", a.Findings, 12)
}
