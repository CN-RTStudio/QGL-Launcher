package main

import (
	"fmt"
	"strings"
)

const (
	playerCacheFileName         = "usercache.json"
	playerCacheMaxBytes         = int64(1) << 20
	playerCacheMaxEntries       = 65536
	playerCacheReasonOK         = "ok"
	playerCacheReasonSymlink    = "symlink"
	playerCacheReasonNotRegular = "not-regular"
	playerCacheReasonTooLarge   = "too-large"
	playerCacheReasonBadJSON    = "bad-json"
	playerCacheReasonUnreadable = "unreadable"
	playerCacheReasonDuplicate  = "duplicate-uuid"
	playerCacheReasonBadUUID    = "bad-uuid"
	playerCacheReasonBadName    = "bad-name"
	playerCacheReasonBadExpiry  = "bad-expiry"
	playerCacheReasonTooMany    = "too-many-entries"
)

type PlayerCacheEntry struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	ExpiresOn string `json:"expiresOn"`
}

type PlayerCacheFinding struct {
	Entry    int
	Reason   string
	Detail   string
	Blocking bool
}

type PlayerCacheAudit struct {
	Path     string
	Present  bool
	Entries  int
	Expired  int
	Findings []PlayerCacheFinding
}

func (audit PlayerCacheAudit) Blocking() bool {
	return anyBlocking(audit.Findings, func(f PlayerCacheFinding) bool { return f.Blocking })
}

func (audit PlayerCacheAudit) HasWarnings() bool {
	return len(audit.Findings) > 0 && !audit.Blocking()
}

func (audit PlayerCacheAudit) Codes() []string {
	return findingCodes(audit.Findings, func(f PlayerCacheFinding) string { return f.Reason })
}

func (audit PlayerCacheAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "玩家缓存校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("#%d(%s:%s)", finding.Entry, finding.Reason, finding.Detail))
	}
	return strings.Join(parts, "；")
}

func playerNameValid(name string) bool {
	if len(name) < 3 || len(name) > 16 {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return false
	}
	return true
}
