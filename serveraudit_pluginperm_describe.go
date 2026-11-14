package main

import (
	"fmt"
	"strings"
)

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
