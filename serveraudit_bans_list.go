package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func AuditServerBanList(serverDir string) BanListAudit {
	audit := BanListAudit{Dir: serverDir}
	seenPlayer := map[string]bool{}
	seenIP := map[string]bool{}
	now := time.Now()

	for _, name := range banFiles {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		audit.Files = append(audit.Files, name)
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(name, banReasonSymlink, "封禁名单是符号链接", true)
			continue
		}
		if !info.Mode().IsRegular() {
			audit.add(name, banReasonUnreadable, "封禁名单不是普通文件", true)
			continue
		}
		if info.Size() > banMaxFileBytes {
			audit.add(name, banReasonTooLarge, "封禁名单过大", true)
			continue
		}
		data, err := readBoundedFile(path, auditTextReadMaxBytes)
		if err != nil {
			audit.add(name, banReasonUnreadable, "封禁名单不可读", true)
			continue
		}
		var entries []banEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			audit.add(name, banReasonInvalidJSON, "封禁名单不是合法 JSON 数组", true)
			continue
		}
		if len(entries) > banMaxEntries {
			audit.add(name, banReasonTooMany, "封禁条目数超过预算", true)
			continue
		}
		for _, entry := range entries {
			if !banTextSane(entry.Reason) || !banTextSane(entry.Source) {
				audit.add(name, banReasonBadReason, "封禁理由含控制字符或超长", false)
			}
			if expires, ok := banParseExpiry(entry.Expires); !ok {
				audit.add(name, banReasonBadExpiry, "到期时间无法解析: "+banShorten(entry.Expires), true)
			} else if !expires.IsZero() && expires.Before(now) {
				audit.add(name, banReasonStale, "封禁已过期但仍在名单: "+banShorten(entry.Name+entry.IP), false)
			}
			if name == "banned-players.json" {
				if !wlIsCanonicalUUID(entry.UUID) {
					audit.add(name, banReasonBadUUID, "UUID 不是规范格式: "+banShorten(entry.UUID), true)
					continue
				}
				if !wlNameValid(entry.Name) {
					audit.add(name, banReasonBadName, "玩家名非法或为空: "+banShorten(entry.Name), true)
					continue
				}
				key := strings.ToLower(entry.Name) + "|" + entry.UUID
				if seenPlayer[key] {
					audit.add(name, banReasonDuplicate, "重复封禁玩家: "+banShorten(entry.Name), false)
				}
				seenPlayer[key] = true
				continue
			}
			ipReason, blocking := banCheckIP(entry)
			if ipReason != "" {
				audit.add(name, ipReason, "IP 封禁条目不可信: "+banShorten(entry.IP), blocking)
				continue
			}
			key := strings.TrimSpace(entry.IP)
			if seenIP[key] {
				audit.add(name, banReasonDuplicate, "重复封禁地址: "+banShorten(key), false)
			}
			seenIP[key] = true
		}
	}

	if len(audit.Findings) == 0 {
		audit.add("", banReasonOK, "封禁名单一致", false)
	}
	return audit
}

func banShorten(value string) string {
	if len(value) > 32 {
		return value[:29] + "..."
	}
	return value
}

func banParseExpiry(value string) (time.Time, bool) {
	text := strings.TrimSpace(value)
	if text == "" {
		return time.Time{}, true
	}
	if strings.EqualFold(text, "forever") {
		return time.Time{}, true
	}
	layouts := []string{"2006-01-02 15:04:05 -0700", "2006-01-02 15:04:05 -07:00", time.RFC3339}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, text); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}
