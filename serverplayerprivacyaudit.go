package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

type ppOpEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

type PlayerPrivacyFinding struct {
	Source   string
	Reason   string
	Detail   string
	Blocking bool
}

type PlayerPrivacyAudit struct {
	Dir      string
	Files    []string
	Findings []PlayerPrivacyFinding
}

func (a PlayerPrivacyAudit) Blocking() bool {
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a PlayerPrivacyAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != ppReasonOK {
			return true
		}
	}
	return false
}

func (a PlayerPrivacyAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == ppReasonOK {
			continue
		}
		label := f.Source
		if label == "" {
			label = "player-data"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= ppMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "玩家身份数据未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PlayerPrivacyAudit) add(source, reason, detail string, blocking bool) {
	if len(a.Findings) >= ppMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PlayerPrivacyFinding{
		Source:   source,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
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

func ppValidIPv4(raw string) bool {
	parts := strings.Split(raw, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		value := 0
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
			value = value*10 + int(ch-'0')
		}
		if value > 255 {
			return false
		}
	}
	return true
}

func ppAuditOperators(a *PlayerPrivacyAudit, dir string) {
	data := ppLoadJSON(a, dir, "ops.json")
	if len(data) == 0 {
		return
	}
	var entries []ppOpEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("ops.json", ppReasonMalformedJSON, "管理员列表不是合法 JSON 数组", true)
		return
	}
	full := 0
	bypass := 0
	bad := 0
	for _, e := range entries {
		if !ppUUIDPattern.MatchString(strings.ToLower(strings.TrimSpace(e.UUID))) {
			bad++
		}
		if e.Level >= 4 {
			full++
		}
		if e.BypassesPlayerLimit {
			bypass++
		}
	}
	if bad > 0 {
		a.add("ops.json", ppReasonBadName, fmt.Sprintf("%d 条管理员条目 UUID 非法", bad), true)
	}
	if full > 0 {
		a.add("ops.json", ppReasonOpLevel, fmt.Sprintf("%d 个管理员拥有 4 级权限", full), false)
	}
	if bypass > 0 {
		a.add("ops.json", ppReasonBypassLimit, fmt.Sprintf("%d 个管理员绕过人数上限", bypass), false)
	}
}

func ppAuditOnlineMode(a *PlayerPrivacyAudit, dir string) {
	path := filepath.Join(dir, "server.properties")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	data, readErr := readBoundedFile(path, 1<<20)
	if readErr != nil {
		return
	}
	props := pxParseProperties(string(data))
	if value, ok := props["online-mode"]; ok {
		if strings.EqualFold(strings.TrimSpace(value), "false") {
			a.add("server.properties", ppReasonOnlineMode, "在线模式关闭，玩家身份可被冒充", false)
		}
	}
}

func ppAuditLogIP(a *PlayerPrivacyAudit, dir string) {
	path := filepath.Join(dir, "logs", "latest.log")
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Size() > ppMaxLogBytes {
		return
	}
	data, readErr := readBoundedFile(path, ppMaxLogBytes)
	if readErr != nil {
		return
	}
	hits := len(ppLogIP.FindAllString(string(data), -1))
	if hits > ppMaxLogIPCount {
		a.add("logs/latest.log", ppReasonLogIPLeak, fmt.Sprintf("日志残留 %d 处明文地址", hits), false)
	}
}

func AuditServerPlayerPrivacy(serverDir string) PlayerPrivacyAudit {
	audit := PlayerPrivacyAudit{Dir: serverDir}
	root, err := filepath.Abs(serverDir)
	if err != nil {
		audit.add("server-dir", ppReasonUnreadable, "无法解析服务器目录", true)
		return audit
	}
	audit.Dir = root
	info, statErr := os.Lstat(root)
	if statErr != nil || !info.IsDir() {
		audit.add("server-dir", ppReasonMissing, "服务器目录不存在", true)
		return audit
	}
	now := time.Now()
	ppAuditUserCache(&audit, root, now)
	ppAuditBannedIPs(&audit, root)
	ppAuditOperators(&audit, root)
	ppAuditOnlineMode(&audit, root)
	ppAuditLogIP(&audit, root)
	if len(audit.Findings) == 0 {
		audit.add("player-data", ppReasonOK, "玩家身份数据均在预算内", false)
	}
	return audit
}
