package main

import (
	"fmt"
	"sort"
	"strings"
)

type PluginJarFinding struct {
	Jar      string
	Reason   string
	Detail   string
	Blocking bool
}

type PluginJarAudit struct {
	Dir      string
	Jars     []string
	Findings []PluginJarFinding
}

func (a PluginJarAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginJarFinding) bool { return f.Blocking })
}

func (a PluginJarAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginJarFinding) bool { return !f.Blocking && f.Reason != pjReasonOK })
}

func (a PluginJarAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == pjReasonOK {
			continue
		}
		label := f.Jar
		if label == "" {
			label = "plugins"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= pjMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "插件包结构未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PluginJarAudit) add(jar, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pjMaxFindings, PluginJarFinding{Jar: jar, Reason: reason, Detail: detail, Blocking: blocking})
}
