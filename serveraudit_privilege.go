package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	accessReasonOK         = "ok"
	accessReasonSymlink    = "symlink"
	accessReasonNotRegular = "not-regular"
	accessReasonTooLarge   = "too-large"
	accessReasonMalformed  = "malformed"
	accessReasonTooMany    = "too-many"
	accessReasonBadEntry   = "bad-entry"
	accessReasonDuplicate  = "duplicate"
	accessMaxFileBytes     = 4 << 20
	accessMaxEntries       = 512
	accessMaxNameRunes     = 64
	accessMinOpsLevel      = 1
	accessMaxOpsLevel      = 4
)

var accessFileNames = []string{
	"ops.json",
	"whitelist.json",
	"banned-players.json",
	"banned-ips.json",
}

type AccessFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type AccessFileAudit struct {
	Name     string
	Present  bool
	Symlink  bool
	Entries  int
	Findings []AccessFinding
}

type ServerAccessAudit struct {
	Dir      string
	Files    []AccessFileAudit
	Findings []AccessFinding
}

type accessRecord struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Level   int    `json:"level"`
	IP      string `json:"ip"`
	Expires string `json:"expires"`
}

func auditAccessFile(serverDir, name string) (AccessFileAudit, error) {
	out := AccessFileAudit{Name: name}
	path := filepath.Join(serverDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	out.Present = true
	if info.Mode()&os.ModeSymlink != 0 {
		out.Symlink = true
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonSymlink, Detail: "权限文件是符号链接", Blocking: true,
		})
		return out, nil
	}
	if !info.Mode().IsRegular() {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonNotRegular, Detail: "权限文件不是普通文件", Blocking: true,
		})
		return out, nil
	}
	if info.Size() > accessMaxFileBytes {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonTooLarge,
			Detail:   fmt.Sprintf("权限文件体积 %d 字节超过上限 %d", info.Size(), accessMaxFileBytes),
			Blocking: true,
		})
		return out, nil
	}
	raw, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		return out, err
	}
	records, err := parseAccessRecords(raw)
	if err != nil {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonMalformed, Detail: "JSON 结构无法解析", Blocking: true,
		})
		return out, nil
	}
	out.Entries = len(records)
	if len(records) > accessMaxEntries {
		out.Findings = append(out.Findings, AccessFinding{
			File: name, Reason: accessReasonTooMany,
			Detail:   fmt.Sprintf("记录数 %d 超过上限 %d", len(records), accessMaxEntries),
			Blocking: true,
		})
	}
	out.Findings = append(out.Findings, auditAccessRecords(name, records)...)
	return out, nil
}

func parseAccessRecords(raw []byte) ([]accessRecord, error) {
	var records []accessRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func auditAccessRecords(file string, records []accessRecord) []AccessFinding {
	findings := []AccessFinding{}
	seenUUID := map[string]int{}
	for index, record := range records {
		entry := strings.TrimSpace(record.UUID)
		if entry == "" {
			entry = fmt.Sprintf("#%d", index+1)
		}
		if file == "banned-ips.json" {
			findings = append(findings, auditBannedIP(file, entry, record)...)
			continue
		}
		if reason, detail := validateAccessUUID(record.UUID); reason != "" {
			findings = append(findings, AccessFinding{File: file, Entry: entry, Reason: reason, Detail: detail, Blocking: true})
		}
		if reason, detail := validateAccessName(record.Name); reason != "" {
			findings = append(findings, AccessFinding{File: file, Entry: entry, Reason: reason, Detail: detail, Blocking: true})
		}
		normalized := normalizeAccessUUID(record.UUID)
		if normalized != "" {
			if first, ok := seenUUID[normalized]; ok {
				findings = append(findings, AccessFinding{
					File: file, Entry: entry, Reason: accessReasonDuplicate,
					Detail: fmt.Sprintf("与第 %d 条记录 UUID 重复", first+1), Blocking: true,
				})
			} else {
				seenUUID[normalized] = index
			}
		}
		if file == "ops.json" && record.Level != 0 {
			if record.Level < accessMinOpsLevel || record.Level > accessMaxOpsLevel {
				findings = append(findings, AccessFinding{
					File: file, Entry: entry, Reason: accessReasonBadEntry,
					Detail:   fmt.Sprintf("op 等级 %d 超出 %d-%d", record.Level, accessMinOpsLevel, accessMaxOpsLevel),
					Blocking: true,
				})
			} else if record.Level == accessMaxOpsLevel {
				findings = append(findings, AccessFinding{
					File: file, Entry: entry, Reason: accessReasonBadEntry,
					Detail: "op 等级 4 拥有完全控制权", Blocking: false,
				})
			}
		}
	}
	return findings
}

func auditBannedIP(file, entry string, record accessRecord) []AccessFinding {
	if reason, detail := validateAccessIP(record.IP); reason != "" {
		return []AccessFinding{{File: file, Entry: entry, Reason: reason, Detail: detail, Blocking: true}}
	}
	ip := net.ParseIP(strings.TrimSpace(record.IP))
	if ip == nil {
		return nil
	}
	findings := []AccessFinding{}
	if ip.IsUnspecified() {
		findings = append(findings, AccessFinding{
			File: file, Entry: entry, Reason: accessReasonBadEntry,
			Detail: "封禁 0.0.0.0/:: 会拒绝全部地址", Blocking: true,
		})
	}
	if ip.IsLoopback() {
		findings = append(findings, AccessFinding{
			File: file, Entry: entry, Reason: accessReasonBadEntry,
			Detail: "封禁回环地址没有实际意义", Blocking: false,
		})
	}
	return findings
}

func validateAccessIP(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 ip 字段"
	}
	if len(value) > 64 {
		return accessReasonBadEntry, "ip 字段长度超限"
	}
	if net.ParseIP(value) == nil {
		return accessReasonBadEntry, "ip 字段不是合法地址"
	}
	return "", ""
}

func validateAccessUUID(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 uuid 字段"
	}
	normalized := normalizeAccessUUID(value)
	if len(normalized) != 32 || !IsLowerHex(normalized, 32) {
		return accessReasonBadEntry, "uuid 不是 32 位十六进制"
	}
	return "", ""
}

func normalizeAccessUUID(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.ReplaceAll(value, "-", "")
	return value
}

func validateAccessName(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 name 字段"
	}
	if utf8.RuneCountInString(value) > accessMaxNameRunes {
		return accessReasonBadEntry, fmt.Sprintf("name 超过 %d 字符", accessMaxNameRunes)
	}
	if containsControlByte(value) {
		return accessReasonBadEntry, "name 含控制字符"
	}
	if strings.ContainsAny(value, "/\\:\"'") {
		return accessReasonBadEntry, "name 含路径或引号字符"
	}
	return "", ""
}

func (a ServerAccessAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}
func (a ServerAccessAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}
func (a ServerAccessAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, finding := range a.Findings {
		if seen[finding.Reason] {
			continue
		}
		seen[finding.Reason] = true
		codes = append(codes, finding.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a ServerAccessAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "服务器权限文件未发现异常"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		if finding.Entry != "" {
			parts = append(parts, fmt.Sprintf("%s[%s]: %s", finding.File, finding.Entry, finding.Detail))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", finding.File, finding.Detail))
		}
	}
	return strings.Join(parts, "；")
}

func AuditServerAccess(serverDir string) (ServerAccessAudit, error) {
	audit := ServerAccessAudit{Dir: serverDir}
	for _, name := range accessFileNames {
		fileAudit, err := auditAccessFile(serverDir, name)
		if err != nil {
			return audit, err
		}
		audit.Files = append(audit.Files, fileAudit)
		audit.Findings = append(audit.Findings, fileAudit.Findings...)
	}
	return audit, nil
}

const (
	acReasonOK             = "ok"
	acReasonMissing        = "missing"
	acReasonUnreadable     = "unreadable"
	acReasonTooLarge       = "too-large"
	acReasonMalformed      = "malformed"
	acReasonSymlink        = "symlink"
	acReasonOfflineMode    = "offline-mode"
	acReasonOpTooHigh      = "op-level-too-high"
	acReasonWhitelistOff   = "whitelist-disabled"
	acReasonDuplicateEntry = "duplicate-entry"
	acReasonMissingField   = "missing-field"

	acMaxJSONBytes = 1 << 20
	acMaxEntries   = 4096
	acMaxFindings  = 64
)

type AccessControlFinding = auditFinding

type AccessControlAudit struct {
	Dir      string
	Sources  []string
	Findings []AccessControlFinding
}

func (a AccessControlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AccessControlFinding) bool { return f.Blocking })
}

func (a AccessControlAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f AccessControlFinding) bool { return !f.Blocking && f.Reason != acReasonOK })
}

func acInspectOps(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "ops.json")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("ops.json", acReasonUnreachable(err), "无法读取 ops.json", true)
		return
	}
	var entries []opEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		audit.add("ops.json", acReasonMalformed, "ops.json 不是合法的操作员列表", true)
		return
	}
	if len(entries) > acMaxEntries {
		audit.add("ops.json", acReasonTooLarge, "操作员条目超过预算", true)
		return
	}
	seenUUID := map[string]int{}
	seenName := map[string]int{}
	for i, entry := range entries {
		if strings.TrimSpace(entry.UUID) == "" || strings.TrimSpace(entry.Name) == "" {
			audit.add("ops.json", acReasonMissingField, fmt.Sprintf("第 %d 项缺少 uuid 或 name", i+1), true)
			continue
		}
		normalized := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", ""))
		if len(normalized) != 32 {
			audit.add("ops.json", acReasonMalformed, fmt.Sprintf("第 %d 项 uuid 长度异常", i+1), true)
		}
		if _, ok := seenUUID[normalized]; ok {
			audit.add("ops.json", acReasonDuplicateEntry, fmt.Sprintf("重复 uuid 条目: %s", entry.Name), false)
		}
		seenUUID[normalized] = i
		lowerName := strings.ToLower(entry.Name)
		if _, ok := seenName[lowerName]; ok {
			audit.add("ops.json", acReasonDuplicateEntry, fmt.Sprintf("重复操作员: %s", entry.Name), false)
		}
		seenName[lowerName] = i
		if entry.Level >= 4 {
			audit.add("ops.json", acReasonOpTooHigh, fmt.Sprintf("%s 拥有 4 级操作员权限", entry.Name), true)
		}
		if entry.Level < 0 || entry.Level > 4 {
			audit.add("ops.json", acReasonMalformed, fmt.Sprintf("%s 操作员等级越界", entry.Name), true)
		}
		if entry.BypassesPlayerCap {
			audit.add("ops.json", acReasonOpTooHigh, fmt.Sprintf("%s 可绕过人数上限", entry.Name), false)
		}
	}
	audit.Sources = append(audit.Sources, "ops.json")
}

func acInspectWhitelist(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "whitelist.json")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("whitelist.json", acReasonUnreachable(err), "无法读取 whitelist.json", true)
		return
	}
	var entries []whitelistEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		audit.add("whitelist.json", acReasonMalformed, "whitelist.json 不是合法的白名单", true)
		return
	}
	if len(entries) > acMaxEntries {
		audit.add("whitelist.json", acReasonTooLarge, "白名单条目超过预算", true)
		return
	}
	for i, entry := range entries {
		if strings.TrimSpace(entry.UUID) == "" || strings.TrimSpace(entry.Name) == "" {
			audit.add("whitelist.json", acReasonMissingField, fmt.Sprintf("第 %d 项缺少 uuid 或 name", i+1), true)
		}
	}
	audit.Sources = append(audit.Sources, "whitelist.json")
}

func acInspectBans(audit *AccessControlAudit, dir, name string) {
	path := filepath.Join(dir, name)
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add(name, acReasonUnreachable(err), "无法读取封禁列表", true)
		return
	}
	var entries []bannedEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		audit.add(name, acReasonMalformed, "封禁列表不是合法 JSON", true)
		return
	}
	for i, entry := range entries {
		identifier := strings.TrimSpace(entry.UUID)
		if identifier == "" {
			identifier = strings.TrimSpace(entry.IP)
		}
		if identifier == "" {
			audit.add(name, acReasonMissingField, fmt.Sprintf("第 %d 项缺少 uuid 与 ip", i+1), true)
		}
		if strings.Contains(entry.IP, "*") {
			audit.add(name, acReasonMalformed, "封禁条目使用通配 IP，可能误封整段地址", false)
		}
	}
	audit.Sources = append(audit.Sources, name)
}

func acInspectProperties(audit *AccessControlAudit, dir string) {
	path := filepath.Join(dir, "server.properties")
	body, err := readBoundedFile(path, acMaxJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		audit.add("server.properties", acReasonUnreachable(err), "无法读取服务端属性", true)
		return
	}
	audit.Sources = append(audit.Sources, "server.properties")
	values := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		values[key] = strings.TrimSpace(line[eq+1:])
	}
	if mode, ok := values["online-mode"]; ok && strings.EqualFold(mode, "false") {
		audit.add("server.properties", acReasonOfflineMode, "online-mode=false 允许伪造用户名登录", true)
	}
	if white, ok := values["white-list"]; ok && strings.EqualFold(white, "false") {
		audit.add("server.properties", acReasonWhitelistOff, "白名单已关闭", false)
	}
	if enforce, ok := values["enforce-whitelist"]; ok && strings.EqualFold(enforce, "false") {
		audit.add("server.properties", acReasonWhitelistOff, "白名单未强制生效", false)
	} else if !ok {
		if white, ok2 := values["white-list"]; ok2 && strings.EqualFold(white, "true") {
			audit.add("server.properties", acReasonWhitelistOff, "启用白名单但未设置 enforce-whitelist", false)
		}
	}
}

func acReasonUnreachable(err error) string {
	if strings.Contains(err.Error(), "符号链接") {
		return acReasonSymlink
	}
	if strings.Contains(err.Error(), "体积") {
		return acReasonTooLarge
	}
	return acReasonUnreadable
}

func AuditServerAccessControl(serverDir string) AccessControlAudit {
	audit := AccessControlAudit{Dir: serverDir}
	info, err := os.Stat(serverDir)
	if err != nil || !info.IsDir() {
		audit.add("", acReasonMissing, "服务器目录不存在", true)
		return audit
	}
	acInspectProperties(&audit, serverDir)
	acInspectOps(&audit, serverDir)
	acInspectWhitelist(&audit, serverDir)
	acInspectBans(&audit, serverDir, "banned-players.json")
	acInspectBans(&audit, serverDir, "banned-ips.json")
	if len(audit.Sources) == 0 {
		audit.add("", acReasonMissing, "未发现访问控制配置", false)
	}
	if len(audit.Findings) == 0 {
		audit.add("", acReasonOK, "访问控制配置未发现风险", false)
	}
	return audit
}

func (a AccessControlAudit) Describe() string {
	return describeTaggedFindings("访问控制未发现风险", a.Findings, acReasonOK, "server", acMaxFindings,
		func(f AccessControlFinding) string { return f.Reason },
		func(f AccessControlFinding) string { return f.File },
		func(f AccessControlFinding) string { return f.Detail })
}

func (a *AccessControlAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, acMaxFindings, AccessControlFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

type opEntry struct {
	UUID              string `json:"uuid"`
	Name              string `json:"name"`
	Level             int    `json:"level"`
	BypassesPlayerCap bool   `json:"bypassesPlayerLimit"`
}

type whitelistEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type bannedEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Reason  string `json:"reason"`
	Created string `json:"created"`
}
