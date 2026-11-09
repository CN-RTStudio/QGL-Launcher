package main

import (
	"regexp"
)

const (
	ppReasonOK            = "ok"
	ppReasonMissing       = "missing"
	ppReasonSymlink       = "symlink"
	ppReasonTooLarge      = "too-large"
	ppReasonWorldWritable = "world-writable"
	ppReasonWorldReadable = "world-readable"
	ppReasonUnreadable    = "unreadable"
	ppReasonMalformedJSON = "malformed-json"
	ppReasonOverflow      = "entry-overflow"
	ppReasonStaleEntry    = "stale-entry"
	ppReasonDuplicateUUID = "duplicate-uuid"
	ppReasonBadName       = "bad-player-name"
	ppReasonOpLevel       = "full-op-level"
	ppReasonBypassLimit   = "bypass-player-limit"
	ppReasonBannedAll     = "banned-all-addresses"
	ppReasonInvalidIP     = "invalid-ip"
	ppReasonOnlineMode    = "offline-mode"
	ppReasonLogIPLeak     = "log-ip-leak"

	ppMaxJSONBytes  = 1 << 20
	ppMaxLogBytes   = 8 << 20
	ppMaxEntries    = 5000
	ppMaxStaleDays  = 500
	ppMaxFindings   = 48
	ppMaxLogIPCount = 0
)

var (
	ppUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	ppIPPattern   = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	ppLogIP       = regexp.MustCompile(`(\d{1,3}\.){3}\d{1,3}`)
	ppNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)
)

type ppUserEntry struct {
	Name      string `json:"name"`
	UUID      string `json:"uuid"`
	ExpiresOn string `json:"expiresOn"`
}

type ppBanEntry struct {
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Expires string `json:"expires"`
}
