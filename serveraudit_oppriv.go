package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
