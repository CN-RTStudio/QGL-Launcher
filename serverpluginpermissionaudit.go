package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
	for _, f := range a.Findings {
		if f.Blocking {
			return true
		}
	}
	return false
}

func (a PluginPermissionAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != plugPermReasonOK {
			return true
		}
	}
	return false
}

func (a PluginPermissionAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == plugPermReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
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
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != plugPermReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", a.Files, len(a.Findings), blocking, warnings)
}

func (a *PluginPermissionAudit) add(file string, line int, reason, detail string, blocking bool) {
	if len(a.Findings) >= plugPermMaxFindings {
		return
	}
	a.Findings = append(a.Findings, PluginPermFinding{File: file, Line: line, Reason: reason, Detail: detail, Blocking: blocking})
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
