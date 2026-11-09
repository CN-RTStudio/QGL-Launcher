package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func wlUUIDVersion(value string) int {
	if len(value) < 15 {
		return 0
	}
	ch := value[14]
	if ch >= '0' && ch <= '9' {
		return int(ch - '0')
	}
	if ch >= 'a' && ch <= 'f' {
		return int(ch-'a') + 10
	}
	return 0
}

func wlNameValid(name string) bool {
	if name == "" || len(name) > 16 {
		return false
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x21 || ch == 0x7f {
			return false
		}
		switch ch {
		case '"', '\'', '\\', '/', ';', '&', '|', '$', '<', '>':
			return false
		}
	}
	return true
}

type wlEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

func wlLoadEntries(path string) ([]wlEntry, string) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, wlReasonMissing
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, wlReasonSymlink
	}
	if !info.Mode().IsRegular() {
		return nil, wlReasonUnreadable
	}
	if info.Size() > wlMaxFileBytes {
		return nil, wlReasonTooLarge
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return nil, wlReasonUnreadable
	}
	var entries []wlEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, wlReasonInvalidJSON
	}
	return entries, ""
}

func wlLoadRawShape(path string) (bool, string) {
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return false, wlReasonUnreadable
	}
	var probe []map[string]interface{}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false, wlReasonInvalidJSON
	}
	for _, item := range probe {
		if _, ok := item["uuid"]; !ok {
			return false, wlReasonBadShape
		}
	}
	return true, ""
}

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
				audit.add(name, wlReasonBadUUID, "UUID 不是规范格式: "+wlShorten(entry.UUID), true)
				continue
			}
			if !wlNameValid(entry.Name) {
				audit.add(name, wlReasonBadName, "玩家名非法或为空: "+wlShorten(entry.Name), true)
				continue
			}
			version := wlUUIDVersion(entry.UUID)
			if version == 3 {
				audit.add(name, wlReasonOfflineUUID, "UUID 是离线模式派生值: "+wlShorten(entry.Name), false)
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
					audit.add(name, wlReasonOpBypass, "操作员绕过人数上限: "+wlShorten(entry.Name), false)
				}
			}
			if name == "usercache.json" && entry.UUID != "" {
				if prev, ok := nameUUID[lower]; ok && strings.EqualFold(prev, entry.UUID) == false {
					audit.add(name, wlReasonUUIDMismatch, "同一玩家名绑定了不同 UUID: "+wlShorten(entry.Name), false)
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

func wlShorten(value string) string {
	if len(value) > 32 {
		return value[:29] + "..."
	}
	return value
}
