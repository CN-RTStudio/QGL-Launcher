package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
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

type ppOpEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

type PlayerPrivacyFinding struct {
	Source   string
	Reason   string
	Detail   string
	Blocking bool
}

type PlayerPrivacyAudit struct {
	Dir      string
	Files    []string
	Findings []PlayerPrivacyFinding
}

func (a PlayerPrivacyAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PlayerPrivacyFinding) bool { return f.Blocking })
}

func (a PlayerPrivacyAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PlayerPrivacyFinding) bool { return !f.Blocking && f.Reason != ppReasonOK })
}

func (a PlayerPrivacyAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == ppReasonOK {
			continue
		}
		label := f.Source
		if label == "" {
			label = "player-data"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= ppMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "玩家身份数据未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PlayerPrivacyAudit) add(source, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, ppMaxFindings, PlayerPrivacyFinding{Source: source, Reason: reason, Detail: detail, Blocking: blocking})
}
