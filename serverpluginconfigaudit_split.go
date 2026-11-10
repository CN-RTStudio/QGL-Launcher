package main

import (
	"fmt"
)

type PluginConfigFinding = auditFinding

type PluginConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PluginConfigFinding
}

func (a PluginConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking })
}

func (a PluginConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
}

func (a PluginConfigAudit) Codes() []string {
	return findingCodesSkip(a.Findings, pcReasonOK, func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Describe() string {
	return describeLabeledFindings("未发现插件配置", a.Findings, 4, "",
		func(f PluginConfigFinding) string { return f.File },
		func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking }, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *PluginConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pcMaxFindings, PluginConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
