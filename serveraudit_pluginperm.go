package main

import (
	"strings"
)

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
