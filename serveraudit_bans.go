package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	sbeMaxFindings = 22
	sbeMaxFile     = 512 * 1024
	sbeBadJSON     = "ban-json-invalid"
	sbeNoUUID      = "ban-entry-without-uuid"
	sbeNoReason    = "ban-entry-without-reason"
	sbeOpBanned    = "operator-also-banned"
	sbeWildcard    = "ip-ban-wildcard"
	sbeDupEntry    = "ban-duplicate"
	sbeLink        = "ban-file-symlink"
)

type BanEnforcementFinding = auditFinding
type BanEnforcementAudit struct {
	ServerDir string
	Findings  []BanEnforcementFinding
}

func (a *BanEnforcementAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbeMaxFindings, BanEnforcementFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *BanEnforcementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BanEnforcementFinding) bool { return f.Blocking })
}
func (a *BanEnforcementAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *BanEnforcementAudit) Describe() string {
	return describeFileDetail("封禁与管理员名单未发现冲突", a.Findings, 12)
}

type sbeBan struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}

func sbeLoad(serverDir, name string, a *BanEnforcementAudit) ([]sbeBan, bool) {
	path := filepath.Join(serverDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	if link {
		a.add(name, sbeLink, "名单文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, sbeMaxFile)
	if err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	var list []sbeBan
	if err := json.Unmarshal(data, &list); err != nil {
		a.add(name, sbeBadJSON, err.Error(), true)
		return nil, false
	}
	return list, true
}

func sbeOpNames(serverDir string) map[string]bool {
	data, err := readBoundedFile(filepath.Join(serverDir, "ops.json"), sbeMaxFile)
	if err != nil {
		return map[string]bool{}
	}
	var ops []sbeBan
	if err := json.Unmarshal(data, &ops); err != nil {
		return map[string]bool{}
	}
	out := make(map[string]bool, len(ops))
	for _, op := range ops {
		if key := strings.ToLower(strings.TrimSpace(op.UUID)); key != "" {
			out[key] = true
		}
	}
	return out
}

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

func banCheckIP(entry banEntry) (reason string, blocking bool) {
	ip := strings.TrimSpace(entry.IP)
	if ip == "" {
		return banReasonBadIP, true
	}
	if ip == "*" {
		return banReasonWildcard, true
	}
	if strings.Contains(ip, "/") {
		_, network, err := net.ParseCIDR(ip)
		if err != nil || network == nil {
			return banReasonBadIP, true
		}
		ones, bits := network.Mask.Size()
		if bits == 32 && ones <= 8 {
			return banReasonBroadCIDR, true
		}
		if bits == 128 && ones <= 16 {
			return banReasonBroadCIDR, true
		}
		return "", false
	}
	if net.ParseIP(ip) == nil {
		return banReasonBadIP, true
	}
	return "", false
}

func banTextSane(value string) bool {
	if len(value) > 512 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch < 0x20 && ch != '\t' {
			return false
		}
		if ch == 0x7f {
			return false
		}
	}
	return true
}

func (a BanListAudit) Codes() []string {
	return findingCodesSkip(a.Findings, banReasonOK, func(f BanFinding) string { return f.Reason })
}

func (a BanListAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现封禁名单"
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

func (a BanListAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f BanFinding) bool { return f.Blocking }, func(f BanFinding) bool { return !f.Blocking && f.Reason != banReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *BanListAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, banMaxFindings, BanFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
