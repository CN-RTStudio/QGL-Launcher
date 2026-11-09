package main

import (
	"fmt"
	"sort"
	"strings"
)

type ServerPortFinding = auditFinding

type ServerPortAudit struct {
	Dir      string
	File     string
	BindIP   string
	Ports    map[string]int
	Findings []ServerPortFinding
}

func (a ServerPortAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f ServerPortFinding) bool { return f.Blocking })
}

func (a ServerPortAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f ServerPortFinding) bool { return !f.Blocking && f.Reason != pxReasonOK })
}

func (a ServerPortAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == pxReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "server.properties"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= pxMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务端端口与绑定配置未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *ServerPortAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pxMaxFindings, ServerPortFinding{File: a.File, Reason: reason, Detail: detail, Blocking: blocking})
}
