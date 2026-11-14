package main

import (
	"strconv"
	"strings"
)

func (a TickConfigAudit) Describe() string {
	return describeTaggedFindings("服务端运行参数未发现风险", a.Findings, tkReasonOK, "", tkMaxFindings,
		func(f TickConfigFinding) string { return f.Reason },
		func(f TickConfigFinding) string { return f.File },
		func(f TickConfigFinding) string { return f.Detail })
}
func (a *TickConfigAudit) add(reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, tkMaxFindings, TickConfigFinding{File: "server.properties", Reason: reason, Detail: detail, Blocking: blocking})
}
func tkInt(props map[string]string, key string, fallback int) int {
	raw, ok := props[key]
	if !ok {
		return fallback
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return value
}
