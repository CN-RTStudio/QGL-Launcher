package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func ppAuditUserCache(a *PlayerPrivacyAudit, dir string, now time.Time) {
	data := ppLoadJSON(a, dir, "usercache.json")
	if len(data) == 0 {
		return
	}
	var entries []ppUserEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("usercache.json", ppReasonMalformedJSON, "玩家缓存不是合法 JSON 数组", true)
		return
	}
	if len(entries) > ppMaxEntries {
		a.add("usercache.json", ppReasonOverflow, fmt.Sprintf("缓存条目 %d 条超过上限 %d", len(entries), ppMaxEntries), false)
	}
	seen := map[string]int{}
	stale := 0
	badName := 0
	for _, e := range entries {
		key := strings.ToLower(strings.TrimSpace(e.UUID))
		if key == "" {
			continue
		}
		seen[key]++
		if !ppNamePattern.MatchString(e.Name) {
			badName++
		}
		if ppStaleExpiry(e.ExpiresOn, now) {
			stale++
		}
	}
	dups := 0
	for _, n := range seen {
		if n > 1 {
			dups++
		}
	}
	if dups > 0 {
		a.add("usercache.json", ppReasonDuplicateUUID, fmt.Sprintf("%d 个 UUID 重复登记", dups), false)
	}
	if stale > 0 {
		a.add("usercache.json", ppReasonStaleEntry, fmt.Sprintf("%d 条过期条目未清理", stale), false)
	}
	if badName > 0 {
		a.add("usercache.json", ppReasonBadName, fmt.Sprintf("%d 条玩家名不符合命名规则", badName), false)
	}
}
