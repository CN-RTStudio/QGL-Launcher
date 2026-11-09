package main

import (
	"fmt"
	"strings"
)

type JMXAudit struct {
	Dir      string
	Sources  []string
	Findings []JMXFinding
}

func (a JMXAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f JMXFinding) bool { return f.Blocking })
}

func (a JMXAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f JMXFinding) bool { return !f.Blocking && f.Reason != jmxReasonOK })
}

func (a JMXAudit) Codes() []string {
	return findingCodesSkip(a.Findings, jmxReasonOK, func(f JMXFinding) string { return f.Reason })
}

func (a JMXAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现 JMX 远程管理配置"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}
