package main

import ()

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
