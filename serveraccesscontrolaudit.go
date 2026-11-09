package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	acReasonOK             = "ok"
	acReasonMissing        = "missing"
	acReasonUnreadable     = "unreadable"
	acReasonTooLarge       = "too-large"
	acReasonMalformed      = "malformed"
	acReasonSymlink        = "symlink"
	acReasonOfflineMode    = "offline-mode"
	acReasonOpTooHigh      = "op-level-too-high"
	acReasonWhitelistOff   = "whitelist-disabled"
	acReasonDuplicateEntry = "duplicate-entry"
	acReasonMissingField   = "missing-field"

	acMaxJSONBytes = 1 << 20
	acMaxEntries   = 4096
	acMaxFindings  = 64
)

type AccessControlFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type AccessControlAudit struct {
	Dir      string
	Sources  []string
	Findings []AccessControlFinding
}

func (a AccessControlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AccessControlFinding) bool { return f.Blocking })
}

func (a AccessControlAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != acReasonOK {
			return true
		}
	}
	return false
}

func (a AccessControlAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == acReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "server"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= acMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "访问控制未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *AccessControlAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= acMaxFindings {
		return
	}
	a.Findings = append(a.Findings, AccessControlFinding{
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

type opEntry struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Level             int    `json:"level"`
	BypassesPlayerCap bool   `json:"bypassesPlayerLimit"`
}

type whitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type bannedEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}
