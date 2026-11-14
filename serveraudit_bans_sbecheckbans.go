package main

import (
	"strings"
)

func sbeCheckBans(serverDir, file string, list []sbeBan, ops map[string]bool, a *BanEnforcementAudit, ipMode bool) {
	seen := make(map[string]int, len(list))
	for _, ban := range list {
		key := strings.ToLower(strings.TrimSpace(ban.UUID))
		if ipMode {
			key = strings.ToLower(strings.TrimSpace(ban.IP))
			if key == "*" || strings.HasSuffix(key, ".*") {
				a.add(file, sbeWildcard, "网段通配封禁: "+ban.IP, false)
			}
		} else if key == "" {
			a.add(file, sbeNoUUID, "封禁条目缺少 UUID: "+ban.Name, false)
		}
		if strings.TrimSpace(ban.Reason) == "" || cfgIsPlaceholder(ban.Reason) {
			a.add(file, sbeNoReason, "封禁无原因: "+ban.Name+ban.IP, false)
		}
		if key != "" {
			seen[key]++
			if seen[key] == 2 {
				a.add(file, sbeDupEntry, "重复封禁: "+key, false)
			}
		}
		if !ipMode && ops[key] {
			a.add(file, sbeOpBanned, "管理员同时被封禁: "+ban.Name, true)
		}
	}
}

func AuditServerBanEnforcement(serverDir string) *BanEnforcementAudit {
	a := &BanEnforcementAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("banned-players.json", sbeBadJSON, "未配置服务器目录", false)
		return a
	}
	ops := sbeOpNames(serverDir)
	if list, ok := sbeLoad(serverDir, "banned-players.json", a); ok {
		sbeCheckBans(serverDir, "banned-players.json", list, ops, a, false)
	}
	if list, ok := sbeLoad(serverDir, "banned-ips.json", a); ok {
		sbeCheckBans(serverDir, "banned-ips.json", list, ops, a, true)
	}
	return a
}

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
