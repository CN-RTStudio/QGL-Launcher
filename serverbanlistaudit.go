package main

const (
	banReasonOK          = "ok"
	banReasonMissing     = "missing"
	banReasonUnreadable  = "unreadable"
	banReasonTooLarge    = "too-large"
	banReasonTooMany     = "too-many"
	banReasonSymlink     = "symlink"
	banReasonInvalidJSON = "invalid-json"
	banReasonBadUUID     = "bad-uuid"
	banReasonBadName     = "bad-name"
	banReasonBadIP       = "bad-ip"
	banReasonWildcard    = "wildcard-ban"
	banReasonBroadCIDR   = "broad-cidr"
	banReasonStale       = "stale-ban"
	banReasonBadExpiry   = "bad-expiry"
	banReasonDuplicate   = "duplicate-entry"
	banReasonBadReason   = "bad-reason"

	banMaxFileBytes = 1 << 20
	banMaxEntries   = 1024
	banMaxFindings  = 96
)

var banFiles = []string{"banned-players.json", "banned-ips.json"}

type BanFinding = auditFinding

type BanListAudit struct {
	Dir      string
	Files    []string
	Findings []BanFinding
}

func (a BanListAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BanFinding) bool { return f.Blocking })
}

func (a BanListAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f BanFinding) bool { return !f.Blocking && f.Reason != banReasonOK })
}
