package main

import (
	"encoding/json"
	"errors"
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

const (
	operatorReasonOK         = "ok"
	operatorReasonTooLarge   = "too-large"
	operatorReasonSymlink    = "symlink"
	operatorReasonNotRegular = "not-regular"
	operatorReasonUnreadable = "unreadable"
	operatorReasonBadJSON    = "bad-json"
	operatorReasonDuplicate  = "duplicate"
	operatorReasonBadUUID    = "bad-uuid"
	operatorReasonBadName    = "bad-name"
	operatorReasonBadLevel   = "bad-level"

	operatorMaxBytes = 1 << 20
)

var operatorFileNames = []string{"ops.json", "whitelist.json", "banned-players.json"}

type OperatorFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}
type ServerOperatorAudit struct {
	Files    map[string]int
	Findings []OperatorFinding
}
type operatorEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               int    `json:"level"`
	BypassesPlayerLimit bool   `json:"bypassesPlayerLimit"`
}

func (a *ServerOperatorAudit) Blocking() bool {
	if a == nil {
		return false
	}
	return anyBlocking(a.Findings, func(f OperatorFinding) bool { return f.Blocking })
}

func (a *ServerOperatorAudit) HasWarnings() bool {
	return a != nil && len(a.Findings) > 0
}

func (a *ServerOperatorAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f OperatorFinding) string { return f.Reason })
}

func (a *ServerOperatorAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "服务器权限名单一致"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s/%s(%s): %s", f.File, f.Entry, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}

func AuditServerOperators(serverDir string) (*ServerOperatorAudit, error) {
	audit := &ServerOperatorAudit{Files: map[string]int{}}
	for _, name := range operatorFileNames {
		path := filepath.Join(serverDir, name)
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("读取 %s 失败: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonSymlink,
				Detail: "权限名单是符号链接", Blocking: true,
			})
			continue
		}
		if !info.Mode().IsRegular() {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonNotRegular,
				Detail: "权限名单不是普通文件", Blocking: true,
			})
			continue
		}
		if info.Size() > operatorMaxBytes {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonTooLarge,
				Detail: fmt.Sprintf("超过 %d 字节上限", operatorMaxBytes), Blocking: true,
			})
			continue
		}
		data, err := readBoundedFile(path, auditTextReadMaxBytes)
		if err != nil {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonUnreadable, Detail: "无法读取文件", Blocking: false,
			})
			continue
		}
		var entries []operatorEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			audit.Findings = append(audit.Findings, OperatorFinding{
				File: name, Reason: operatorReasonBadJSON,
				Detail: "JSON 无法解析，服务器会按空名单处理", Blocking: false,
			})
			continue
		}
		audit.Files[name] = len(entries)
		audit.auditEntries(name, entries)
	}
	return audit, nil
}

func (a *ServerOperatorAudit) auditEntries(file string, entries []operatorEntry) {
	seenUUID := map[string]int{}
	seenName := map[string]int{}
	for index, entry := range entries {
		label := strings.TrimSpace(entry.Name)
		if label == "" {
			label = fmt.Sprintf("#%d", index+1)
		}
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if uuid == "" || !operatorValidUUID(uuid) {
			a.Findings = append(a.Findings, OperatorFinding{
				File: file, Entry: label, Reason: operatorReasonBadUUID,
				Detail: "UUID 缺失或格式不是 36 位带连字符的十六进制", Blocking: false,
			})
		} else {
			seenUUID[uuid]++
			if seenUUID[uuid] == 2 {
				a.Findings = append(a.Findings, OperatorFinding{
					File: file, Entry: label, Reason: operatorReasonDuplicate,
					Detail: "同一 UUID 出现多次，权限判定依赖解析顺序", Blocking: false,
				})
			}
		}
		name := strings.ToLower(strings.TrimSpace(entry.Name))
		if name != "" {
			seenName[name]++
			if seenName[name] == 2 {
				a.Findings = append(a.Findings, OperatorFinding{
					File: file, Entry: label, Reason: operatorReasonDuplicate,
					Detail: "同一玩家名出现多次", Blocking: false,
				})
			}
			if containsControlByte(entry.Name) {
				a.Findings = append(a.Findings, OperatorFinding{
					File: file, Entry: label, Reason: operatorReasonBadName,
					Detail: "玩家名包含控制字符", Blocking: false,
				})
			}
		}
		if file == "ops.json" && (entry.Level < 1 || entry.Level > 4) {
			a.Findings = append(a.Findings, OperatorFinding{
				File: file, Entry: label, Reason: operatorReasonBadLevel,
				Detail: fmt.Sprintf("OP 等级 %d 超出原版 1~4 范围", entry.Level), Blocking: false,
			})
		}
	}
}

func operatorValidUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		ch := value[index]
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !IsLowerHex(string(ch), 1) {
			return false
		}
	}
	return true
}

const (
	soaMaxFindings  = 32
	soaMaxFile      = 512 * 1024
	soaMaxOperators = 64
	soaMaxLevel     = 4
	soaBusyOps      = 8
	soaReasonMiss   = "missing"
	soaReasonLink   = "symlink"
	soaReasonLarge  = "too-large"
	soaReasonRead   = "unreadable"
	soaReasonShape  = "invalid-shape"
	soaReasonLargeN = "too-many-operators"
	soaReasonUUID   = "invalid-uuid"
	soaReasonName   = "invalid-name"
	soaReasonLevel  = "invalid-level"
	soaReasonBypass = "invalid-bypass-flag"
	soaReasonDup    = "duplicate-operator"
	soaReasonOwner  = "owner-level-operator"
	soaReasonBusy   = "many-privileged-operators"
	soaReasonEmpty  = "empty-operator-list"
)

type OpsJsonFinding = auditFinding
type OpsJsonAudit struct {
	ServerDir string
	Findings  []OpsJsonFinding
}
type opsJsonEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               *int   `json:"level"`
	BypassesPlayerLimit *bool  `json:"bypassesPlayerLimit"`
}

func (a *OpsJsonAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, soaMaxFindings, OpsJsonFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OpsJsonAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OpsJsonFinding) bool { return f.Blocking })
}

func (a *OpsJsonAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsJsonAudit) Describe() string {
	return describeFileReasonDetail("服务器操作员清单未发现风险", a.Findings, 12)
}

func soaValidUUID(value string) bool {
	if len(value) != 36 && len(value) != 32 {
		return false
	}
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

func soaValidName(value string) bool {
	return propsValidName(value)
}

func AuditServerOpsJson(serverDir string) *OpsJsonAudit {
	a := &OpsJsonAudit{ServerDir: serverDir}
	const rel = "ops.json"
	if serverDir == "" {
		a.add(".", soaReasonMiss, "未配置服务器目录", false)
		return a
	}
	if info, err := os.Lstat(serverDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		a.add(".", soaReasonLink, "服务器目录为符号链接", true)
		return a
	}
	path := filepath.Join(serverDir, rel)
	if sym, serr := isSymlinkOrSpecial(path); serr == nil && sym {
		a.add(rel, soaReasonLink, "操作员清单为符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, soaMaxFile)
	if err != nil {
		if _, serr := os.Lstat(path); serr != nil {
			return a
		}
		if errors.Is(err, errLocalFileTooLarge) {
			a.add(rel, soaReasonLarge, fmt.Sprintf("操作员清单超过 %d 字节", soaMaxFile), true)
			return a
		}
		a.add(rel, soaReasonRead, "操作员清单不可读", false)
		return a
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		a.add(rel, soaReasonEmpty, "操作员清单为空文件", false)
		return a
	}
	var entries []opsJsonEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		a.add(rel, soaReasonShape, "操作员清单不是合法的 JSON 数组", true)
		return a
	}
	if len(entries) > soaMaxOperators {
		a.add(rel, soaReasonLargeN, fmt.Sprintf("操作员数量 %d 超过 %d", len(entries), soaMaxOperators), true)
	}
	if len(entries) == 0 {
		a.add(rel, soaReasonEmpty, "操作员清单为空数组", false)
		return a
	}

	seenUUID := make(map[string]bool, len(entries))
	seenName := make(map[string]bool, len(entries))
	privileged := 0
	for i, entry := range entries {
		label := fmt.Sprintf("#%d", i+1)
		if strings.TrimSpace(entry.UUID) == "" {
			a.add(rel, soaReasonUUID, label+" 缺少 uuid", true)
		} else if !soaValidUUID(entry.UUID) {
			a.add(rel, soaReasonUUID, label+" uuid 格式非法", true)
		} else {
			key := strings.ToLower(strings.ReplaceAll(entry.UUID, "-", ""))
			if seenUUID[key] {
				a.add(rel, soaReasonDup, label+" uuid 重复", false)
			}
			seenUUID[key] = true
		}
		if !soaValidName(entry.Name) {
			a.add(rel, soaReasonName, label+" 玩家名非法", true)
		} else {
			key := strings.ToLower(entry.Name)
			if seenName[key] {
				a.add(rel, soaReasonDup, label+" 玩家名重复", false)
			}
			seenName[key] = true
		}
		if entry.Level == nil {
			a.add(rel, soaReasonLevel, label+" 缺少 level 字段", true)
		} else if *entry.Level < 0 || *entry.Level > soaMaxLevel {
			a.add(rel, soaReasonLevel, label+" level 超出 0..4", true)
		} else {
			if *entry.Level >= 2 {
				privileged++
			}
			if *entry.Level == soaMaxLevel {
				a.add(rel, soaReasonOwner, label+" 具备服务器所有权限", false)
			}
		}
		if entry.BypassesPlayerLimit == nil {
			a.add(rel, soaReasonBypass, label+" 缺少 bypassesPlayerLimit 布尔值", false)
		}
	}
	if privileged > soaBusyOps {
		a.add(rel, soaReasonBusy, fmt.Sprintf("%d 名操作员拥有二级以上权限", privileged), false)
	}
	return a
}

const (
	syoMaxFile     = 512 * 1024
	syoMaxFindings = 20
	syoMaxOps      = 64
	syoMaxLevel    = 4
	syoMissing     = "ops-file-missing"
	syoUnreadable  = "ops-file-unreadable"
	syoSymlink     = "ops-file-symlink"
	syoBadJSON     = "ops-json-invalid"
	syoEmpty       = "ops-entry-empty"
	syoOfflineUUID = "ops-offline-uuid"
	syoBadUUID     = "ops-uuid-malformed"
	syoOverLevel   = "ops-level-too-high"
	syoBadLevel    = "ops-level-missing"
	syoDuplicate   = "ops-duplicate-uuid"
	syoTooMany     = "ops-entry-limit"
	syoByName      = "ops-name-underspecified"
	syoBypass      = "ops-bypass-enabled"
)

type OpsEntry struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Level   int    `json:"level"`
	Bypass  bool   `json:"bypassesPlayerLimit"`
	Banned  bool   `json:"-"`
	HasName bool   `json:"-"`
}
type OpsPrivilegeFinding struct {
	Reason   string
	Detail   string
	Blocking bool
}

type OpsPrivilegeAudit struct {
	ServerDir string
	Entries   int
	Findings  []OpsPrivilegeFinding
}

func (a *OpsPrivilegeAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, syoMaxFindings, OpsPrivilegeFinding{Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OpsPrivilegeAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OpsPrivilegeFinding) bool { return f.Blocking })
}

func (a *OpsPrivilegeAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsPrivilegeAudit) Describe() string {
	return describeAuditFindings("运维权限配置未发现风险", a.Findings, 10,
		func(f OpsPrivilegeFinding) []string {
			return []string{f.Reason, f.Detail}
		},
		func(f OpsPrivilegeFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func syoUUIDShape(uuid string) string {
	clean := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(uuid)), "-", "")
	if len(clean) != 32 {
		return syoBadUUID
	}
	for _, r := range clean {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return syoBadUUID
		}
	}
	if clean[12] == '3' && strings.ContainsRune("89ab", rune(clean[16])) {
		return syoOfflineUUID
	}
	return ""
}
func syoParse(data []byte, a *OpsPrivilegeAudit) []OpsEntry {
	text := strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	if text == "" || text == "[]" {
		a.add(syoEmpty, "ops.json 为空，无任何运维账号", false)
		return nil
	}
	var entries []OpsEntry
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		a.add(syoBadJSON, err.Error(), true)
		return nil
	}
	return entries
}

func AuditServerOpsPrivilege(serverDir string) *OpsPrivilegeAudit {
	a := &OpsPrivilegeAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add(syoMissing, "未配置服务器目录", true)
		return a
	}
	path := filepath.Join(serverDir, "ops.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(syoMissing, "缺少 ops.json", false)
		return a
	}
	bad, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(syoUnreadable, err.Error(), true)
		return a
	}
	if bad {
		a.add(syoSymlink, "ops.json 是符号链接或特殊文件", true)
		return a
	}
	data, err := readBoundedFile(path, syoMaxFile)
	if err != nil {
		a.add(syoUnreadable, err.Error(), true)
		return a
	}
	entries := syoParse(data, a)
	a.Entries = len(entries)
	if len(entries) > syoMaxOps {
		a.add(syoTooMany, fmt.Sprintf("运维账号 %d 个，超过 %d 上限", len(entries), syoMaxOps), true)
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		uuid := strings.ToLower(strings.TrimSpace(entry.UUID))
		if kind := syoUUIDShape(uuid); kind != "" {
			a.add(kind, uuid, true)
		}
		if _, dup := seen[uuid]; dup && uuid != "" {
			a.add(syoDuplicate, uuid, true)
		}
		seen[uuid] = struct{}{}
		if entry.Level < 0 || entry.Level > syoMaxLevel {
			a.add(syoOverLevel, fmt.Sprintf("level=%d 超出 0..%d", entry.Level, syoMaxLevel), true)
		}
		if entry.Level == 0 {
			a.add(syoBadLevel, "level=0 的运维账号无法执行管理命令", false)
		}
		if strings.TrimSpace(entry.Name) == "" {
			a.add(syoByName, "运维账号缺少 name 字段", false)
		}
		if entry.Bypass {
			a.add(syoBypass, fmt.Sprintf("%s 可绕过满员限制", uuid), false)
		}
	}
	return a
}

const (
	pmReasonOK            = "ok"
	pmReasonMissing       = "missing"
	pmReasonSymlink       = "symlink"
	pmReasonTooLarge      = "too-large"
	pmReasonWorldWritable = "world-writable"
	pmReasonUnreadable    = "unreadable"
	pmReasonWildcardGrant = "wildcard-grant"
	pmReasonDefaultOp     = "default-op"
	pmReasonDefaultAllow  = "default-allow"
	pmReasonOpCommand     = "op-command-grant"
	pmReasonUnknownNode   = "unknown-plugin-node"
	pmReasonTooManyFiles  = "file-overflow"

	pmMaxFileBytes = 512 << 10
	pmMaxFiles     = 24
	pmMaxFindings  = 48
)

var pmCandidateFiles = []string{
	"permissions.yml",
	"config/permissions.yml",
	"plugins/PluginPermissions/permissions.yml",
}

var pmDangerousNodes = []string{
	"bukkit.command.op",
	"minecraft.command.op",
	"bukkit.command.stop",
	"bukkit.command.reload",
	"essentials.give",
	"worldedit.*",
}

type PermissionConfigFinding = auditFinding
type PermissionConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PermissionConfigFinding
}

func (a PermissionConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PermissionConfigFinding) bool { return f.Blocking })
}
func (a PermissionConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PermissionConfigFinding) bool { return !f.Blocking && f.Reason != pmReasonOK })
}

func (a PermissionConfigAudit) Describe() string {
	return describeTaggedFindings("权限配置未发现越权授予", a.Findings, pmReasonOK, "permissions", pmMaxFindings,
		func(f PermissionConfigFinding) string { return f.Reason },
		func(f PermissionConfigFinding) string { return f.File },
		func(f PermissionConfigFinding) string { return f.Detail })
}
func (a *PermissionConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pmMaxFindings, PermissionConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func pmCollect(root string) []string {
	found := []string{}
	for _, name := range pmCandidateFiles {
		path := filepath.Join(root, filepath.FromSlash(name))
		if _, err := os.Lstat(path); err == nil {
			found = append(found, path)
		}
	}
	pluginsDir := filepath.Join(root, "plugins")
	entries, err := os.ReadDir(pluginsDir)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, name := range []string{"permissions.yml", "permissions.yaml"} {
			path := filepath.Join(pluginsDir, entry.Name(), name)
			if _, err := os.Lstat(path); err == nil {
				found = append(found, path)
			}
		}
	}
	sort.Strings(found)
	return found
}

func pmInspectFile(a *PermissionConfigAudit, root, path string) {
	rel, data, ok := inspectAuditTextFile(a.add, &a.Files, root, path, pmFileCheck)
	if !ok {
		return
	}
	pmScanText(a, rel, string(data))
}

func pmScanText(a *PermissionConfigAudit, rel, text string) {
	lines := strings.Split(text, "\n")
	wildcard := 0
	defaultOp := 0
	defaultAllow := 0
	opCommand := 0
	unknown := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "- ") || strings.HasPrefix(lower, "\"") {
			node := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(lower, "- "), "\""))
			node = strings.Trim(node, "\"'")
			if node == "*" || strings.HasSuffix(node, ":*") {
				wildcard++
			}
			if node == "*:*" || node == "bukkit.*" || node == "minecraft.*" {
				wildcard++
			}
			for _, danger := range pmDangerousNodes {
				if node == danger {
					opCommand++
				}
			}
			if strings.Contains(node, "command.") && strings.Contains(node, "op") {
				opCommand++
			}
			continue
		}
		colon := strings.Index(lower, ":")
		if colon <= 0 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(lower[:colon]), "\"'")
		value := strings.Trim(strings.TrimSpace(lower[colon+1:]), "\"'")
		switch key {
		case "default":
			switch value {
			case "op":
				defaultOp++
			case "true", "yes", "allow":
				defaultAllow++
			}
		case "*":
			wildcard++
		case "permission", "node":
			if value == "*" {
				wildcard++
			}
		}
		if key == "description" && strings.Contains(value, "unknown") {
			unknown++
		}
	}
	if wildcard > 0 {
		a.add(rel, pmReasonWildcardGrant, fmt.Sprintf("%d 处通配权限授予", wildcard), true)
	}
	if defaultOp > 0 {
		a.add(rel, pmReasonDefaultOp, fmt.Sprintf("%d 个节点默认授予 op", defaultOp), false)
	}
	if defaultAllow > 0 {
		a.add(rel, pmReasonDefaultAllow, fmt.Sprintf("%d 个节点默认对所有玩家开放", defaultAllow), false)
	}
	if opCommand > 0 {
		a.add(rel, pmReasonOpCommand, fmt.Sprintf("%d 处命令类权限越权授予", opCommand), false)
	}
	if unknown > 0 {
		a.add(rel, pmReasonUnknownNode, fmt.Sprintf("%d 个节点来源未标注", unknown), false)
	}
}

func AuditServerPermissionConfig(serverDir string) PermissionConfigAudit {
	audit := PermissionConfigAudit{Dir: serverDir}
	if root := scanAuditRoot(serverDir, pmRootScan, pmCollect, func(root, path string) { pmInspectFile(&audit, root, path) }, audit.add, func() int { return len(audit.Findings) }); root != "" {
		audit.Dir = root
	}
	return audit
}

const (
	smnMaxFindings   = 32
	smnMaxFile       = 256 * 1024
	smnMaxEntries    = 400
	smnMaxInherit    = 3
	smnReasonMiss    = "missing"
	smnReasonLink    = "symlink"
	smnReasonLarge   = "too-large"
	smnReasonRead    = "unreadable"
	smnReasonEmpty   = "empty-config"
	smnReasonDefault = "default-oversized"
	smnReasonWild    = "wildcard-permission"
	smnReasonInherit = "inherit-depth"
	smnReasonNode    = "invalid-node"
	smnReasonCTRL    = "control-characters"
	smnReasonOpGrant = "op-grant"
	smnReasonBusy    = "too-many-entries"
	smnReasonUserOp  = "user-op-default"
)

type PermissionsFinding = auditFinding

type PermissionsAudit struct {
	ServerDir string
	Findings  []PermissionsFinding
}

func (a *PermissionsAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, smnMaxFindings, PermissionsFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
func (a *PermissionsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PermissionsFinding) bool { return f.Blocking })
}
func (a *PermissionsAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}
func (a *PermissionsAudit) Describe() string {
	return describeReasonDetail("permissions.yml 未发现风险", a.Findings, 12)
}

type smnEntry struct {
	Path  string
	Value string
}

func smnValidNode(node string) bool {
	if node == "" || len(node) > 128 {
		return false
	}
	if strings.HasPrefix(node, ".") || strings.HasSuffix(node, ".") {
		return false
	}
	if strings.Contains(node, "..") || strings.Contains(node, " ") {
		return false
	}
	for _, r := range node {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func AuditServerPermissions(serverDir string) *PermissionsAudit {
	a := &PermissionsAudit{ServerDir: serverDir}
	if serverDir == "" {
		a.add("permissions.yml", smnReasonMiss, "未配置服务器目录", false)
		return a
	}
	const rel = "permissions.yml"
	path := filepath.Join(serverDir, rel)
	link, err := isSymlinkOrSpecial(path)
	if err != nil {
		a.add(rel, smnReasonRead, err.Error(), true)
		return a
	}
	if link {
		a.add(rel, smnReasonLink, "权限配置是符号链接或特殊文件", true)
		return a
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		a.add(rel, smnReasonMiss, "未找到 permissions.yml", false)
		return a
	}
	data, err := readBoundedFile(path, smnMaxFile)
	if err != nil {
		reason := smnReasonRead
		if err == errLocalFileTooLarge {
			reason = smnReasonLarge
		}
		a.add(rel, reason, err.Error(), true)
		return a
	}
	text := string(data)
	if strings.TrimSpace(text) == "" {
		a.add(rel, smnReasonEmpty, "权限配置为空", false)
		return a
	}
	entries := smnEntries(text)
	if len(entries) == 0 {
		a.add(rel, smnReasonEmpty, "权限配置无法解析", false)
		return a
	}
	if raw, ok := cfgLookup(cfgFlattenYAML(text), "default"); ok {
		switch strings.ToLower(cfgStripQuotes(raw)) {
		case "op", "true", "allow":
			a.add(rel, smnReasonDefault, "默认权限为 "+strings.ToLower(cfgStripQuotes(raw)), true)
		}
	}
	if len(entries) > smnMaxEntries {
		a.add(rel, smnReasonBusy, fmt.Sprintf("条目数 %d 超过 %d", len(entries), smnMaxEntries), false)
	}
	inherit := map[string]int{}
	for _, e := range entries {
		path := e.Path
		value := e.Value
		if path == "" {
			continue
		}
		if cfgHasControlChars(value) {
			a.add(rel, smnReasonCTRL, path, true)
		}
		if strings.Contains(path, "inheritance") || strings.Contains(path, "parent") {
			group := strings.Split(path, ".")[1]
			inherit[group]++
			continue
		}
		if strings.HasSuffix(path, "permissions") || strings.Contains(path, "permissions.") {
			group := ""
			parts := strings.Split(path, ".")
			if len(parts) >= 2 && parts[0] == "groups" {
				group = parts[1]
			}
			if value == "*" || strings.HasPrefix(value, "*") || strings.HasSuffix(value, ".*") {
				a.add(rel, smnReasonWild, path+" → "+value, true)
				continue
			}
			if value == "bukkit.command.op" || strings.HasPrefix(value, "bukkit.command.op.") {
				a.add(rel, smnReasonOpGrant, path+" → "+value, true)
				continue
			}
			if !smnValidNode(value) {
				a.add(rel, smnReasonNode, path+" → "+value, false)
			}
			if group != "" && len(group) > 64 {
				a.add(rel, smnReasonNode, "权限组名过长", false)
			}
			continue
		}
		if strings.HasPrefix(path, "users.") {
			parts := strings.Split(path, ".")
			if len(parts) >= 3 && parts[2] == "default" {
				if strings.EqualFold(value, "op") || strings.EqualFold(value, "true") {
					a.add(rel, smnReasonUserOp, parts[1], true)
				}
			}
		}
	}
	for group, depth := range inherit {
		if depth > smnMaxInherit {
			a.add(rel, smnReasonInherit, fmt.Sprintf("%s 继承 %d 层", group, depth), false)
		}
	}
	return a
}

func smnEntries(text string) []smnEntry {
	type frame struct {
		indent int
		key    string
	}
	stack := make([]frame, 0, 8)
	out := make([]smnEntry, 0, 32)
	for _, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) == "" || strings.HasPrefix(strings.TrimSpace(raw), "#") {
			continue
		}
		indent := 0
		for indent < len(raw) && raw[indent] == ' ' {
			indent++
		}
		trimmed := strings.TrimSpace(raw)
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent && !strings.HasPrefix(trimmed, "- ") {
			stack = stack[:len(stack)-1]
		}
		if strings.HasPrefix(trimmed, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			item = cfgStripQuotes(item)
			path := ""
			if len(stack) > 0 {
				path = stack[len(stack)-1].key
			}
			out = append(out, smnEntry{Path: path, Value: item})
			continue
		}
		sep := strings.Index(trimmed, ":")
		if sep < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:sep])
		value := strings.TrimSpace(trimmed[sep+1:])
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		path := key
		if len(stack) > 0 {
			path = stack[len(stack)-1].key + "." + key
		}
		stack = append(stack, frame{indent: indent, key: path})
		if value != "" {
			out = append(out, smnEntry{Path: path, Value: cfgStripQuotes(value)})
		}
	}
	return out
}

const (
	plugPermReasonOK              = "ok"
	plugPermReasonMissing         = "missing"
	plugPermReasonUnreadable      = "unreadable"
	plugPermReasonTooLarge        = "too-large"
	plugPermReasonTooMany         = "too-many"
	plugPermReasonWildcard        = "wildcard-permission"
	plugPermReasonWildcardPlugin  = "wildcard-plugin-permission"
	plugPermReasonOpDefault       = "op-default"
	plugPermReasonEveryPermission = "every-permission-key"
	plugPermMaxFiles              = 60
	plugPermMaxFileBytes          = 512 << 10
	plugPermMaxFindings           = 96
	plugPermMaxDepth              = 3
)

var plugPermFileNames = map[string]bool{
	"config.yml":       true,
	"config.yaml":      true,
	"permissions.yml":  true,
	"permissions.yaml": true,
	"settings.yml":     true,
	"settings.yaml":    true,
	"groups.yml":       true,
	"groups.yaml":      true,
}

type PluginPermFinding struct {
	File     string
	Line     int
	Reason   string
	Detail   string
	Blocking bool
}

type PluginPermissionAudit struct {
	Dir      string
	Files    int
	Findings []PluginPermFinding
}

func (a PluginPermissionAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginPermFinding) bool { return f.Blocking })
}

func plugPermIsWildcard(value string) bool {
	if value == "" {
		return false
	}
	for _, sep := range []string{",", " "} {
		if !strings.Contains(value, sep) {
			continue
		}
		parts := strings.Split(value, sep)
		all := true
		any := false
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			any = true
			if part != "*" && part != "*:*" {
				all = false
				break
			}
		}
		if all && any {
			return true
		}
	}
	return value == "*" || value == "*:*"
}

func plugPermScanFile(audit *PluginPermissionAudit, display string, data []byte) {
	inPermissions := false
	permissionsIndent := -1
	for idx, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		lower := strings.ToLower(trimmed)
		if strings.HasSuffix(lower, "permissions:") || lower == "permissions:" {
			inPermissions = true
			permissionsIndent = indent
			continue
		}
		if inPermissions && indent < permissionsIndent {
			inPermissions = false
		}
		if strings.HasPrefix(lower, "default:") &&
			(strings.Contains(lower, "op") || strings.Contains(lower, "true")) {
			audit.add(display, idx+1, plugPermReasonOpDefault, "插件把默认权限设为 op/true", false)
		}
		if !strings.HasPrefix(trimmed, "-") {
			continue
		}
		value := plugPermValue(line)
		if !plugPermIsWildcard(value) {
			continue
		}
		if strings.Contains(value, ":*") {
			audit.add(display, idx+1, plugPermReasonWildcardPlugin, "插件授予了其他插件的全部权限节点", true)
			continue
		}
		audit.add(display, idx+1, plugPermReasonWildcard, "插件授予了通配权限 *，玩家获得全部能力", true)
		if inPermissions {
			continue
		}
	}
	if strings.Contains(string(data), "permissions:") {
		audit.add(display, 0, plugPermReasonEveryPermission, "配置中声明了 permissions 段，需人工核对继承关系", false)
	}
}

func plugPermInspect(audit *PluginPermissionAudit, path, display string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		audit.add(display, 0, plugPermReasonUnreadable, "插件配置是符号链接", true)
		return
	}
	if !info.Mode().IsRegular() {
		audit.add(display, 0, plugPermReasonUnreadable, "插件配置不是普通文件", true)
		return
	}
	if info.Size() > plugPermMaxFileBytes {
		audit.add(display, 0, plugPermReasonTooLarge, "插件配置超过大小上限", true)
		return
	}
	data, err := readBoundedFile(path, auditTextReadMaxBytes)
	if err != nil {
		audit.add(display, 0, plugPermReasonUnreadable, "插件配置不可读", true)
		return
	}
	audit.Files++
	plugPermScanFile(audit, display, data)
}

func AuditServerPluginPermissions(serverDir string) PluginPermissionAudit {
	audit := PluginPermissionAudit{Dir: serverDir}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", 0, plugPermReasonMissing, "服务器目录不存在", true)
		return audit
	}
	pluginsDir := filepath.Join(serverDir, "plugins")
	if _, err := os.ReadDir(pluginsDir); err != nil {
		audit.add("plugins", 0, plugPermReasonMissing, "插件目录不存在或不可读", false)
		return audit
	}
	visited := 0
	var walk func(dir, display string, depth int)
	walk = func(dir, display string, depth int) {
		if depth > plugPermMaxDepth || visited >= plugPermMaxFiles {
			return
		}
		list, err := os.ReadDir(dir)
		if err != nil {
			audit.add(display, 0, plugPermReasonUnreadable, "插件子目录不可读", false)
			return
		}
		for _, entry := range list {
			if visited >= plugPermMaxFiles {
				audit.add(display, 0, plugPermReasonTooMany, "插件配置文件数量超过上限", true)
				return
			}
			name := entry.Name()
			child := filepath.Join(dir, name)
			if entry.IsDir() {
				walk(child, filepath.Join(display, name), depth+1)
				continue
			}
			if !plugPermFileNames[strings.ToLower(name)] {
				continue
			}
			visited++
			plugPermInspect(&audit, child, filepath.Join(display, name))
		}
	}
	walk(pluginsDir, "plugins", 1)
	if len(audit.Findings) == 0 {
		audit.add("", 0, plugPermReasonOK, "插件配置未声明通配权限", false)
	}
	return audit
}

func (a PluginPermissionAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginPermFinding) bool { return !f.Blocking && f.Reason != plugPermReasonOK })
}
func (a PluginPermissionAudit) Codes() []string {
	return findingCodesSkip(a.Findings, plugPermReasonOK, func(f PluginPermFinding) string { return f.Reason })
}
func (a PluginPermissionAudit) Describe() string {
	if len(a.Findings) == 0 {
		return fmt.Sprintf("已扫描 %d 个插件配置，未发现通配权限", a.Files)
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s:%d(%s)", f.File, f.Line, f.Reason))
		if len(parts) >= 5 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a PluginPermissionAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f PluginPermFinding) bool { return f.Blocking }, func(f PluginPermFinding) bool { return !f.Blocking && f.Reason != plugPermReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", a.Files, len(a.Findings), blocking, warnings)
}

func (a *PluginPermissionAudit) add(file string, line int, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, plugPermMaxFindings, PluginPermFinding{File: file, Line: line, Reason: reason, Detail: detail, Blocking: blocking})
}

func plugPermValue(line string) string {
	text := strings.TrimSpace(line)
	text = strings.TrimLeft(text, "-")
	text = strings.TrimSpace(text)
	text = strings.ReplaceAll(text, `"`, "")
	text = strings.ReplaceAll(text, "'", "")
	text = strings.TrimSpace(text)
	if idx := strings.Index(text, " #"); idx >= 0 {
		text = strings.TrimSpace(text[:idx])
	}
	return text
}
