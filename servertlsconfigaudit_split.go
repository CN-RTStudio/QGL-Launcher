package main

import (
	"fmt"
	"sort"
	"strings"
)

type TLSAudit struct {
	Dir      string
	Files    []string
	Findings []TLSFinding
}

func (a TLSAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f TLSFinding) bool { return f.Blocking })
}

func (a TLSAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f TLSFinding) bool { return !f.Blocking && f.Reason != tlsReasonOK })
}

func (a TLSAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == tlsReasonOK {
			continue
		}
		label := f.Key
		if label == "" {
			label = "tls"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= tlsMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "TLS 配置未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *TLSAudit) add(key, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, tlsMaxFindings, TLSFinding{Key: key, Reason: reason, Detail: detail, Blocking: blocking})
}

func tlsParse(body string) map[string]string {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		values[strings.TrimSpace(line[:eq])] = strings.TrimSpace(line[eq+1:])
	}
	return values
}
