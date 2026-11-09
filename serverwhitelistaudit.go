package main

import (
	"fmt"
	"strings"
)

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

type WhitelistFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

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

func (a WhitelistAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现白名单与操作员配置"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a WhitelistAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != wlReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *WhitelistAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= wlMaxFindings {
		return
	}
	a.Findings = append(a.Findings, WhitelistFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func wlIsCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		ch := value[i]
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') && !(ch >= 'A' && ch <= 'F') {
				return false
			}
		}
	}
	return true
}
