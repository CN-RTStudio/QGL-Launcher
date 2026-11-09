package main

import (
	"fmt"
	"sort"
	"strings"
)

type YamlHazardFinding = auditFinding

type YamlHazardAudit struct {
	Dir      string
	Files    []string
	Findings []YamlHazardFinding
}

func (a YamlHazardAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f YamlHazardFinding) bool { return f.Blocking })
}

func (a YamlHazardAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f YamlHazardFinding) bool { return !f.Blocking && f.Reason != yhReasonOK })
}

func (a YamlHazardAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == yhReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "yaml"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= yhMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "YAML 配置未发现构造风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *YamlHazardAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, yhMaxFindings, YamlHazardFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
