package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
