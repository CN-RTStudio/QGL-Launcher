package main

import (
	"fmt"
	"strings"
)

func (a *ServerResourcePackAudit) HasWarnings() bool {
	if a == nil {
		return false
	}
	return auditHasWarning(a.Findings, func(f PackFinding) bool { return !f.Blocking && f.Reason != packReasonOK })
}

func (a *ServerResourcePackAudit) Codes() []string {
	if a == nil {
		return nil
	}
	return findingCodesSkip(a.Findings, packReasonOK, func(f PackFinding) string { return f.Reason })
}

func (a *ServerResourcePackAudit) Describe() string {
	if a == nil {
		return ""
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		if f.Reason == packReasonOK {
			continue
		}
		if f.Key == "" {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Reason, f.Detail))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%q(%s): %s", f.Key, f.Value, f.Reason, f.Detail))
	}
	return strings.Join(parts, "；")
}
