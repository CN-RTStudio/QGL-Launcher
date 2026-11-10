package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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
