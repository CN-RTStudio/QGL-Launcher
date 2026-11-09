package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func ppStaleExpiry(raw string, now time.Time) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return true
	}
	layouts := []string{time.RFC3339, "2006-01-02 15:04:05 -0700", "2006-01-02T15:04:05.999999999Z"}
	for _, layout := range layouts {
		ts, err := time.Parse(layout, raw)
		if err == nil {
			return now.Sub(ts) > ppMaxStaleDays*24*time.Hour
		}
	}
	return true
}

func ppAuditBannedIPs(a *PlayerPrivacyAudit, dir string) {
	data := ppLoadJSON(a, dir, "banned-ips.json")
	if len(data) == 0 {
		return
	}
	var entries []ppBanEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("banned-ips.json", ppReasonMalformedJSON, "封禁列表不是合法 JSON 数组", true)
		return
	}
	if len(entries) > ppMaxEntries {
		a.add("banned-ips.json", ppReasonOverflow, fmt.Sprintf("封禁条目 %d 条超过上限 %d", len(entries), ppMaxEntries), false)
	}
	invalid := 0
	for _, e := range entries {
		ip := strings.TrimSpace(e.IP)
		if ip == "*" || ip == "" {
			a.add("banned-ips.json", ppReasonBannedAll, "封禁规则覆盖全部地址", false)
			continue
		}
		if !ppIPPattern.MatchString(ip) && !strings.Contains(ip, ":") {
			invalid++
		} else if ppIPPattern.MatchString(ip) && !ppValidIPv4(ip) {
			invalid++
		}
	}
	if invalid > 0 {
		a.add("banned-ips.json", ppReasonInvalidIP, fmt.Sprintf("%d 条封禁规则地址格式非法", invalid), false)
	}
}
