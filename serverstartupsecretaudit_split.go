package main

import (
	"fmt"
	"sort"
	"strings"
)

type StartupSecretFinding = auditFinding

type StartupSecretAudit struct {
	Dir      string
	Files    []string
	Findings []StartupSecretFinding
}

func (a StartupSecretAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StartupSecretFinding) bool { return f.Blocking })
}

func (a StartupSecretAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f StartupSecretFinding) bool { return !f.Blocking && f.Reason != skReasonOK })
}

func (a StartupSecretAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == skReasonOK {
			continue
		}
		label := f.File
		if label == "" {
			label = "startup"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= skMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "启动脚本未发现明文凭据"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *StartupSecretAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, skMaxFindings, StartupSecretFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
