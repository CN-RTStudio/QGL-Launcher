package main

import (
	"fmt"
	"strings"
)

func (a *ServerOperatorAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodes(a.Findings, func(f OperatorFinding) string { return f.Reason })
}

func (a *ServerOperatorAudit) Describe() string {
	if a == nil {
		return ""
	}
	if len(a.Findings) == 0 {
		return "服务器权限名单一致"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s/%s(%s): %s", f.File, f.Entry, f.Reason, f.Detail))
	}
	return strings.Join(parts, "; ")
}
