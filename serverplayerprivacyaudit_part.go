package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ppLoadJSON(a *PlayerPrivacyAudit, dir, name string) []byte {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			a.add(name, ppReasonMissing, "缺少玩家数据文件", false)
		}
		return nil
	}
	a.Files = append(a.Files, name)
	if info.Mode()&os.ModeSymlink != 0 {
		a.add(name, ppReasonSymlink, "玩家数据文件是符号链接", true)
		return nil
	}
	if info.Size() > ppMaxJSONBytes {
		a.add(name, ppReasonTooLarge, "玩家数据文件超过体积预算", true)
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		a.add(name, ppReasonWorldWritable, "玩家数据文件可被其他用户改写", true)
	}
	if info.Mode().Perm()&0o004 != 0 {
		a.add(name, ppReasonWorldReadable, "玩家数据文件对其他用户可读", false)
	}
	data, readErr := readBoundedFile(path, ppMaxJSONBytes)
	if readErr != nil {
		a.add(name, ppReasonUnreadable, "玩家数据文件不可读", true)
		return nil
	}
	return data
}

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
