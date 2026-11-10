package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
