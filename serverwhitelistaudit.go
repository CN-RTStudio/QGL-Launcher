package main

const (
	wlReasonOK             = "ok"
	wlReasonMissing        = "missing"
	wlReasonUnreadable     = "unreadable"
	wlReasonTooLarge       = "too-large"
	wlReasonTooMany        = "too-many"
	wlReasonSymlink        = "symlink"
	wlReasonInvalidJSON    = "invalid-json"
	wlReasonBadShape       = "bad-shape"
	wlReasonBadUUID        = "bad-uuid"
	wlReasonBadName        = "bad-name"
	wlReasonDuplicateUUID  = "duplicate-uuid"
	wlReasonDuplicateName  = "duplicate-name"
	wlReasonOfflineUUID    = "offline-uuid"
	wlReasonBadOpLevel     = "bad-op-level"
	wlReasonOpBypass       = "op-bypass"
	wlReasonUUIDMismatch   = "uuid-mismatch"
	wlReasonEmptyWhitelist = "empty-whitelist"

	wlMaxFileBytes = 512 << 10
	wlMaxEntries   = 512
	wlMaxFindings  = 96
)

var wlFiles = []string{"whitelist.json", "ops.json", "usercache.json"}

type WhitelistFinding = auditFinding

type WhitelistAudit struct {
	Dir      string
	Files    []string
	Findings []WhitelistFinding
}

func (a WhitelistAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistFinding) bool { return f.Blocking })
}

func (a WhitelistAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f WhitelistFinding) bool { return !f.Blocking && f.Reason != wlReasonOK })
}

func (a WhitelistAudit) Codes() []string {
	return findingCodesSkip(a.Findings, wlReasonOK, func(f WhitelistFinding) string { return f.Reason })
}
