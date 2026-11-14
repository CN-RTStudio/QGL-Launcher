package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func AuditServerWhitelist(serverDir string) WhitelistAudit {
	audit := WhitelistAudit{Dir: serverDir}
	seenUUID := map[string]string{}
	seenName := map[string]string{}
	nameUUID := map[string]string{}
	var whitelist []wlEntry

	for _, name := range wlFiles {
		path := filepath.Join(serverDir, name)
		entries, reason := wlLoadEntries(path)
		if reason == wlReasonMissing {
			continue
		}
		audit.Files = append(audit.Files, name)
		if reason != "" {
			audit.add(name, reason, "白名单文件不可用", reason == wlReasonSymlink || reason == wlReasonTooLarge || reason == wlReasonInvalidJSON || reason == wlReasonUnreadable)
			continue
		}
		if len(entries) > wlMaxEntries {
			audit.add(name, wlReasonTooMany, "条目数超过预算", true)
			continue
		}
		if ok, shapeReason := wlLoadRawShape(path); !ok {
			detail := "条目缺少 uuid 字段"
			if shapeReason != wlReasonBadShape {
				detail = "白名单文件无法复核结构"
			}
			audit.add(name, shapeReason, detail, true)
		}
		for _, entry := range entries {
			if !wlIsCanonicalUUID(entry.UUID) {
				audit.add(name, wlReasonBadUUID, "UUID 不是规范格式: "+banShorten(entry.UUID), true)
				continue
			}
			if !wlNameValid(entry.Name) {
				audit.add(name, wlReasonBadName, "玩家名非法或为空: "+banShorten(entry.Name), true)
				continue
			}
			version := wlUUIDVersion(entry.UUID)
			if version == 3 {
				audit.add(name, wlReasonOfflineUUID, "UUID 是离线模式派生值: "+banShorten(entry.Name), false)
			}
			uuidKey := name + "|" + entry.UUID
			if prev, ok := seenUUID[uuidKey]; ok {
				audit.add(name, wlReasonDuplicateUUID, "UUID 与 "+prev+" 重复", false)
			} else {
				seenUUID[uuidKey] = name
			}
			lower := strings.ToLower(entry.Name)
			nameKey := name + "|" + lower
			if prev, ok := seenName[nameKey]; ok {
				audit.add(name, wlReasonDuplicateName, "玩家名与 "+prev+" 重复", false)
			} else {
				seenName[nameKey] = name
			}
			if name == "whitelist.json" {
				whitelist = append(whitelist, entry)
				nameUUID[lower] = entry.UUID
			}
			if name == "ops.json" {
				if entry.Level < 0 || entry.Level > 4 {
					audit.add(name, wlReasonBadOpLevel, "操作员等级越界: "+fmt.Sprintf("%d", entry.Level), true)
				}
				if entry.BypassesPlayerLimit {
					audit.add(name, wlReasonOpBypass, "操作员绕过人数上限: "+banShorten(entry.Name), false)
				}
			}
			if name == "usercache.json" && entry.UUID != "" {
				if prev, ok := nameUUID[lower]; ok && strings.EqualFold(prev, entry.UUID) == false {
					audit.add(name, wlReasonUUIDMismatch, "同一玩家名绑定了不同 UUID: "+banShorten(entry.Name), false)
				}
			}
		}
	}

	if len(whitelist) == 0 {
		if _, err := os.Lstat(filepath.Join(serverDir, "whitelist.json")); err == nil {
			audit.add("whitelist.json", wlReasonEmptyWhitelist, "白名单为空文件或空数组", false)
		}
	}
	if len(audit.Findings) == 0 {
		audit.add("", wlReasonOK, "白名单与操作员配置一致", false)
	}
	return audit
}

func (a WhitelistAudit) Describe() string {
	return describeLabeledFindings("未发现白名单与操作员配置", a.Findings, 6, "server",
		func(f WhitelistFinding) string { return f.File },
		func(f WhitelistFinding) string { return f.Reason })
}
func (a WhitelistAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f WhitelistFinding) bool { return f.Blocking }, func(f WhitelistFinding) bool { return !f.Blocking && f.Reason != wlReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *WhitelistAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, wlMaxFindings, WhitelistFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
