package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
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

type banEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
	Source  string `json:"source"`
}

const (
	sbiMaxFindings    = 36
	sbiMaxFile        = 512 * 1024
	sbiMaxEntries     = 2048
	sbiReasonMissing  = "missing"
	sbiReasonSymlink  = "symlink"
	sbiReasonTooLarge = "too-large"
	sbiReasonUnread   = "unreadable"
	sbiReasonParse    = "invalid-json"
	sbiReasonCount    = "too-many-entries"
	sbiReasonAddress  = "invalid-address"
	sbiReasonDup      = "duplicate-address"
	sbiReasonExpiry   = "invalid-expiry"
)

type BannedIPEntry struct {
	IP      string `json:"ip"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
}
type BannedIPFinding = auditFinding
type BannedIPAudit struct {
	ServerDir string
	Findings  []BannedIPFinding
}

func (a *BannedIPAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbiMaxFindings, BannedIPFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BannedIPAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BannedIPFinding) bool { return f.Blocking })
}

func (a *BannedIPAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BannedIPAudit) Describe() string {
	return describeFileReasonDetail("IP 封禁清单未发现风险", a.Findings, 12)
}

func sbiValidAddress(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}
	if net.ParseIP(trimmed) != nil {
		return true
	}
	return false
}

func AuditServerBannedIPs(serverDir string) *BannedIPAudit {
	a := &BannedIPAudit{ServerDir: serverDir}
	const rel = "banned-ips.json"
	if serverDir == "" {
		a.add(".", sbiReasonMissing, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", sbiReasonSymlink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, sbiReasonSymlink, "封禁清单为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, sbiMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, sbiReasonTooLarge, fmt.Sprintf("封禁清单超过 %d 字节", sbiMaxFile), true)
			return a
		}
		a.add(rel, sbiReasonUnread, "封禁清单不可读", false)
		return a
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		a.add(rel, sbiReasonParse, "封禁清单为空", true)
		return a
	}
	var entries []BannedIPEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(rel, sbiReasonParse, "封禁清单不是合法 JSON 数组", true)
		return a
	}
	if len(entries) == 0 {
		return a
	}
	if len(entries) > sbiMaxEntries {
		a.add(rel, sbiReasonCount, fmt.Sprintf("封禁条目 %d 超过上限", len(entries)), true)
	}
	seen := map[string]string{}
	for index, entry := range entries {
		label := fmt.Sprintf("#%d", index)
		address := strings.TrimSpace(entry.IP)
		if !sbiValidAddress(address) {
			a.add(rel, sbiReasonAddress, label+" IP 地址非法", true)
			continue
		}
		normalized := strings.ToLower(address)
		if net.ParseIP(normalized) != nil {
			normalized = net.ParseIP(normalized).String()
		}
		if previous, exists := seen[normalized]; exists {
			a.add(rel, sbiReasonDup, label+" 与 "+previous+" 重复", false)
		} else {
			seen[normalized] = label
		}
		if strings.TrimSpace(entry.Expires) == "" && strings.TrimSpace(entry.Created) == "" {
			a.add(rel, sbiReasonExpiry, label+" 缺少封禁时间信息", false)
		}
		if cfgHasControlChars(entry.Source) {
			a.add(rel, sbiReasonAddress, label+" 来源字段含控制字符", true)
		}
	}
	return a
}

const (
	sbpMaxFindings  = 32
	sbpMaxFile      = 512 * 1024
	sbpMaxEntries   = 2000
	sbpReasonMiss   = "missing"
	sbpReasonLink   = "symlink"
	sbpReasonLarge  = "too-large"
	sbpReasonRead   = "unreadable"
	sbpReasonShape  = "invalid-shape"
	sbpReasonLargeN = "too-many-entries"
	sbpReasonUUID   = "invalid-uuid"
	sbpReasonName   = "invalid-name"
	sbpReasonTime   = "invalid-timestamp"
	sbpReasonReason = "unsafe-reason"
	sbpReasonDup    = "duplicate-uuid"
	sbpReasonPerm   = "many-permanent-bans"
)

type BannedPlayerFinding = auditFinding

type BannedPlayerAudit struct {
	ServerDir string
	Findings  []BannedPlayerFinding
}

func (a *BannedPlayerAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbpMaxFindings, BannedPlayerFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BannedPlayerAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BannedPlayerFinding) bool { return f.Blocking })
}

func (a *BannedPlayerAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BannedPlayerAudit) Describe() string {
	return describeReasonDetail("banned-players.json 未发现风险", a.Findings, 12)
}

type sbpEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Created string `json:"created"`
	Source  string `json:"source"`
	Expires string `json:"expires"`
	Reason  string `json:"reason"`
}

var sbpUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var sbpNamePattern = regexp.MustCompile(`^[A-Za-z0-9_]{1,16}$`)

func sbpParseTime(value string) bool {
	if value == "" || value == "forever" || value == "infinite" {
		return true
	}
	layouts := []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02 15:04:05 -0700"}
	for _, layout := range layouts {
		if _, err := time.Parse(layout, value); err == nil {
			return true
		}
	}
	return false
}

func AuditServerBannedPlayers(serverDir string) *BannedPlayerAudit {
	a := &BannedPlayerAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("banned-players.json", sbpReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "banned-players.json"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, sbpReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, sbpReasonLink, "封禁名单是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, sbpReasonMiss, "未找到封禁名单", false)
		return a
	}
	data, err := readBoundedFile(path, sbpMaxFile)
	if err != nil {
		reason := sbpReasonRead
		if err == errLocalFileTooLarge {
			reason = sbpReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	var entries []sbpEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add(rel, sbpReasonShape, "JSON 结构非法", true)
		return a
	}
	if len(entries) > sbpMaxEntries {
		a.add(rel, sbpReasonLargeN, fmt.Sprintf("条目数 %d 超过上限", len(entries)), false)
	}
	seen := map[string]bool{}
	permanent := 0
	for i, e := range entries {
		detail := fmt.Sprintf("第 %d 条", i+1)
		uuid := strings.ToLower(strings.TrimSpace(e.UUID))
		if !sbpUUIDPattern.MatchString(uuid) {
			a.add(rel, sbpReasonUUID, detail+" uuid 非法", false)
		} else if seen[uuid] {
			a.add(rel, sbpReasonDup, detail+" uuid 重复", true)
		} else {
			seen[uuid] = true
		}
		if !sbpNamePattern.MatchString(e.Name) {
			a.add(rel, sbpReasonName, detail+" 玩家名非法", false)
		}
		if !sbpParseTime(e.Created) || !sbpParseTime(e.Expires) {
			a.add(rel, sbpReasonTime, detail+" 时间戳非法", false)
		}
		if e.Expires == "" || e.Expires == "forever" || e.Expires == "infinite" {
			permanent++
		}
		if cfgHasControlChars(e.Reason) || cfgHasControlChars(e.Source) {
			a.add(rel, sbpReasonReason, detail+" 附注含控制字符", false)
		}
	}
	if permanent > 50 {
		a.add(rel, sbpReasonPerm, fmt.Sprintf("永久封禁 %d 条", permanent), false)
	}
	return a
}

const (
	serMaxFindings = 24
	serMaxFile     = 64 * 1024
	serReasonMiss  = "missing"
	serReasonLink  = "symlink"
	serReasonLarge = "too-large"
	serReasonRead  = "unreadable"
	serReasonEmpty = "empty-file"
	serReasonDecl  = "eula-not-accepted"
	serReasonDup   = "duplicate-eula-key"
	serReasonConf  = "conflicting-eula-values"
	serReasonCtl   = "control-characters"
)

type EulaFinding = auditFinding
type EulaAudit struct {
	ServerDir string
	Findings  []EulaFinding
}

func (a *EulaAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, serMaxFindings, EulaFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *EulaAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f EulaFinding) bool { return f.Blocking })
}

func (a *EulaAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *EulaAudit) Describe() string {
	return describeFileReasonDetail("EULA 协议文件未发现风险", a.Findings, 12)
}

func serHasControlChars(text string) bool {
	return hasControlCharsText(text)
}

func serParseBool(value string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	}
	return false, false
}

func AuditServerEula(serverDir string) *EulaAudit {
	a := &EulaAudit{ServerDir: serverDir}
	const rel = "eula.txt"
	if serverDir == "" {
		a.add(".", serReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", serReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, serReasonLink, "EULA 文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, serMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			a.add(rel, serReasonMiss, "尚未生成 EULA 协议文件", false)
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, serReasonLarge, fmt.Sprintf("EULA 文件超过 %d 字节", serMaxFile), true)
			return a
		}
		a.add(rel, serReasonRead, "EULA 文件不可读", false)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, serReasonEmpty, "EULA 文件为空", false)
		return a
	}
	if serHasControlChars(text) {
		a.add(rel, serReasonCtl, "EULA 文件含控制字符", true)
	}
	assignments := 0
	accepted := false
	decimal := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		eq := strings.Index(trimmed, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trimmed[:eq], "\ufeff")))
		if key != "eula" {
			continue
		}
		assignments++
		value := cfgStripInlineComment(strings.TrimSpace(trimmed[eq+1:]))
		value = cfgStripQuotes(strings.TrimSpace(value))
		parsed, known := serParseBool(value)
		if !known {
			a.add(rel, serReasonConf, "eula 取值无法识别: "+value, true)
			continue
		}
		if parsed {
			accepted = true
		} else {
			decimal = true
		}
	}
	if assignments == 0 {
		a.add(rel, serReasonDecl, "EULA 文件未声明 eula 字段", false)
		return a
	}
	if assignments > 1 {
		a.add(rel, serReasonDup, fmt.Sprintf("eula 字段重复声明 %d 次", assignments), false)
		if accepted && decimal {
			a.add(rel, serReasonConf, "eula 同时出现接受与拒绝两种取值", true)
		}
	}
	if !accepted {
		a.add(rel, serReasonDecl, "EULA 尚未接受，服务端会拒绝启动", false)
	}
	return a
}

const (
	wlReasonOK             = "ok"
	wlReasonMissing        = "missing"
	wlReasonUnreadable     = "unreadable"
	wlReasonTooLarge       = "too-large"
	wlReasonTooMany        = "too-many"
	wlReasonSymlink        = "symlink"
	wlReasonInvalidJSON    = "invalid-json"
	wlReasonBadShape       = "bad-shape"
	wlReasonBadUUID        = "bad-uuid"
	wlReasonBadName        = "bad-name"
	wlReasonDuplicateUUID  = "duplicate-uuid"
	wlReasonDuplicateName  = "duplicate-name"
	wlReasonOfflineUUID    = "offline-uuid"
	wlReasonBadOpLevel     = "bad-op-level"
	wlReasonOpBypass       = "op-bypass"
	wlReasonUUIDMismatch   = "uuid-mismatch"
	wlReasonEmptyWhitelist = "empty-whitelist"

	wlMaxFileBytes = 512 << 10
	wlMaxEntries   = 512
	wlMaxFindings  = 96
)

var wlFiles = []string{"whitelist.json", "ops.json", "usercache.json"}

type WhitelistFinding = auditFinding

type WhitelistAudit struct {
	Dir      string
	Files    []string
	Findings []WhitelistFinding
}

func (a WhitelistAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistFinding) bool { return f.Blocking })
}

func (a WhitelistAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f WhitelistFinding) bool { return !f.Blocking && f.Reason != wlReasonOK })
}

func (a WhitelistAudit) Codes() []string {
	return findingCodesSkip(a.Findings, wlReasonOK, func(f WhitelistFinding) string { return f.Reason })
}

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

func wlIsCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		ch := value[i]
		switch i {
		case 8, 13, 18, 23:
			if ch != '-' {
				return false
			}
		default:
			if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') && !(ch >= 'A' && ch <= 'F') {
				return false
			}
		}
	}
	return true
}

const (
	swcMaxFindings = 24
	swcMaxFile     = 512 * 1024
	swcMissProps   = "properties-missing"
	swcReadProps   = "properties-unreadable"
	swcOffButList  = "whitelist-off-with-entries"
	swcOnNoFile    = "whitelist-enabled-without-file"
	swcEnforceBad  = "enforce-whitelist-without-whitelist"
	swcBadJSON     = "whitelist-json-invalid"
	swcNoUUID      = "whitelist-entry-without-uuid"
	swcDupName     = "whitelist-duplicate-name"
	swcOpNotListed = "operator-not-whitelisted"
	swcLink        = "whitelist-symlink"
)

type WhitelistCoverageFinding = auditFinding
type WhitelistCoverageAudit struct {
	ServerDir string
	Findings  []WhitelistCoverageFinding
}

func (a *WhitelistCoverageAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swcMaxFindings, WhitelistCoverageFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *WhitelistCoverageAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistCoverageFinding) bool { return f.Blocking })
}
func (a *WhitelistCoverageAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *WhitelistCoverageAudit) Describe() string {
	return describeReasonDetail("白名单覆盖检查通过", a.Findings, 12)
}

type swcEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func swcBool(props map[string]string, key string) (bool, bool) {
	return propsBoolValue(props, key)
}

func swcLoadEntries(serverDir string, a *WhitelistCoverageAudit) ([]swcEntry, bool) {
	path := filepath.Join(serverDir, "whitelist.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, false
	}
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add("whitelist.json", swcReadProps, err.Error(), true)
		return nil, false
	}
	if link {
		a.add("whitelist.json", swcLink, "白名单文件是符号链接或特殊文件", true)
		return nil, false
	}
	data, err := readBoundedFile(path, swcMaxFile)
	if err != nil {
		a.add("whitelist.json", swcReadProps, err.Error(), true)
		return nil, false
	}
	var entries []swcEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		a.add("whitelist.json", swcBadJSON, err.Error(), true)
		return nil, false
	}
	return entries, true
}

func swcOpsNames(serverDir string) []string {
	data, err := readBoundedFile(filepath.Join(serverDir, "ops.json"), swcMaxFile)
	if err != nil {
		return nil
	}
	var ops []swcEntry
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil
	}
	names := make([]string, 0, len(ops))
	for _, op := range ops {
		if name := strings.TrimSpace(op.Name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

func AuditServerWhitelistCoverage(serverDir string) *WhitelistCoverageAudit {
	a := &WhitelistCoverageAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("server.properties", swcMissProps, "未配置服务器目录", false)
		return a
	}
	propsData, err := readBoundedFile(filepath.Join(serverDir, "server.properties"), swcMaxFile)
	if err != nil {
		a.add("server.properties", swcReadProps, "无法读取 server.properties", false)
		return a
	}
	props := pxParseProperties(string(propsData))
	if len(props) == 0 {
		a.add("server.properties", swcReadProps, "属性文件为空", false)
		return a
	}
	white, hasWhite := swcBool(props, "white-list")
	enforce, hasEnforce := swcBool(props, "enforce-whitelist")
	entries, hasFile := swcLoadEntries(serverDir, a)

	if hasEnforce && enforce {
		if !hasWhite || !white {
			a.add("server.properties", swcEnforceBad, "强制白名单已开但白名单本身未启用", true)
		}
		if !hasFile {
			a.add("whitelist.json", swcOnNoFile, "强制白名单却缺少白名单文件", true)
		}
	}
	if hasWhite && white && !hasFile {
		a.add("whitelist.json", swcOnNoFile, "白名单已启用但文件不存在，启动后或被重置", true)
	}
	if hasWhite && !white && hasFile && len(entries) > 0 {
		a.add("whitelist.json", swcOffButList, fmt.Sprintf("白名单关闭但仍有 %d 条记录", len(entries)), false)
	}
	if hasFile {
		seen := make(map[string]int, len(entries))
		for _, entry := range entries {
			name := strings.ToLower(strings.TrimSpace(entry.Name))
			if strings.TrimSpace(entry.UUID) == "" {
				a.add("whitelist.json", swcNoUUID, "条目缺少 UUID: "+entry.Name, false)
			}
			if name != "" {
				seen[name]++
				if seen[name] == 2 {
					a.add("whitelist.json", swcDupName, "重复名称: "+entry.Name, false)
				}
			}
		}
		if ops := swcOpsNames(serverDir); len(ops) > 0 {
			listed := make(map[string]bool, len(entries))
			for _, entry := range entries {
				listed[strings.ToLower(strings.TrimSpace(entry.Name))] = true
			}
			for _, name := range ops {
				if !listed[strings.ToLower(strings.TrimSpace(name))] {
					a.add("whitelist.json", swcOpNotListed, "管理员不在白名单: "+name, false)
				}
			}
		}
	}
	return a
}

const (
	swfMaxFindings = 32
	swfMaxFile     = 512 * 1024
	swfMaxEntries  = 512
	swfReasonMiss  = "missing"
	swfReasonLink  = "symlink"
	swfReasonLarge = "too-large"
	swfReasonRead  = "unreadable"
	swfReasonShape = "invalid-shape"
	swfReasonMany  = "too-many-entries"
	swfReasonUUID  = "invalid-uuid"
	swfReasonName  = "invalid-name"
	swfReasonCtl   = "control-characters"
	swfReasonDup   = "duplicate-entry"
	swfReasonEmpty = "empty-whitelist"
)

type WhitelistFileFinding = auditFinding
type WhitelistFileAudit struct {
	ServerDir string
	Findings  []WhitelistFileFinding
}
type whitelistFileEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func (a *WhitelistFileAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swfMaxFindings, WhitelistFileFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WhitelistFileAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistFileFinding) bool { return f.Blocking })
}

func (a *WhitelistFileAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WhitelistFileAudit) Describe() string {
	return describeFileReasonDetail("服务器白名单文件未发现风险", a.Findings, 12)
}

func swfValidUUID(value string) bool {
	clean := strings.ReplaceAll(value, "-", "")
	if len(clean) != 32 {
		return false
	}
	for _, c := range clean {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func swfValidName(value string) bool {
	return propsValidName(value)
}

func AuditServerWhitelistFile(serverDir string) *WhitelistFileAudit {
	a := &WhitelistFileAudit{ServerDir: serverDir}
	const rel = "whitelist.json"
	if serverDir == "" {
		a.add(".", swfReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", swfReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, swfReasonLink, "白名单文件为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, swfMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, swfReasonLarge, fmt.Sprintf("白名单文件超过 %d 字节", swfMaxFile), true)
			return a
		}
		a.add(rel, swfReasonRead, "白名单文件不可读", false)
		return a
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		a.add(rel, swfReasonShape, "白名单文件为空", true)
		return a
	}
	var entries []whitelistFileEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		a.add(rel, swfReasonShape, "白名单文件不是合法的 JSON 数组", true)
		return a
	}
	if len(entries) > swfMaxEntries {
		a.add(rel, swfReasonMany, fmt.Sprintf("条目数量 %d 超过 %d", len(entries), swfMaxEntries), true)
	}
	if len(entries) == 0 {
		a.add(rel, swfReasonEmpty, "白名单开启但条目为空，所有玩家都会被拒绝", false)
		return a
	}

	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		label := fmt.Sprintf("#%d", i+1)
		if !swfValidUUID(entry.UUID) {
			a.add(rel, swfReasonUUID, label+" uuid 格式非法", true)
		}
		if strings.ContainsAny(entry.Name, "\x00\r\n\t") {
			a.add(rel, swfReasonCtl, label+" 玩家名含控制字符", true)
			continue
		}
		if !swfValidName(entry.Name) {
			a.add(rel, swfReasonName, label+" 玩家名非法", true)
			continue
		}
		key := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", "")) + "/" + strings.ToLower(entry.Name)
		if seen[key] {
			a.add(rel, swfReasonDup, label+" 与前面的条目重复", false)
		}
		seen[key] = true
	}
	return a
}
