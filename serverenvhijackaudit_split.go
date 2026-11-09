package main

import (
	"fmt"
	"strings"
)

type EnvFinding struct {
	Script   string
	Variable string
	Reason   string
	Detail   string
	Blocking bool
}

type EnvHijackAudit struct {
	Dir      string
	Scripts  []string
	Findings []EnvFinding
}

func (a EnvHijackAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f EnvFinding) bool { return f.Blocking })
}

func (a EnvHijackAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f EnvFinding) bool { return !f.Blocking && f.Reason != envReasonOK })
}

func (a EnvHijackAudit) Codes() []string {
	return findingCodesSkip(a.Findings, envReasonOK, func(f EnvFinding) string { return f.Reason })
}

func (a EnvHijackAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现环境变量注入"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s:%s(%s)", f.Script, f.Variable, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a EnvHijackAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f EnvFinding) bool { return f.Blocking }, func(f EnvFinding) bool { return !f.Blocking && f.Reason != envReasonOK })
	return fmt.Sprintf("scripts=%d findings=%d blocking=%d warnings=%d", len(a.Scripts), len(a.Findings), blocking, warnings)
}
