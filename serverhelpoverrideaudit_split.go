package main

import (
	"fmt"
	"sort"
	"strings"
)

var hoKnownFields = []string{
	"shorttext",
	"fulltext",
	"permission",
}

type HelpOverrideFinding struct {
	File     string
	Topic    string
	Reason   string
	Detail   string
	Blocking bool
}

type HelpOverrideAudit struct {
	Dir      string
	Findings []HelpOverrideFinding
	Topics   int
}

func (a HelpOverrideAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f HelpOverrideFinding) bool { return f.Blocking })
}

func (a HelpOverrideAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f HelpOverrideFinding) bool { return !f.Blocking && f.Reason != hoReasonOK })
}

func (a HelpOverrideAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == hoReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail))
		if len(parts) >= hoMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器帮助覆盖未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *HelpOverrideAudit) add(file, topic, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, hoMaxFindings, HelpOverrideFinding{File: file, Topic: topic, Reason: reason, Detail: detail, Blocking: blocking})
}
