package main

import (
	"strings"
)

func (a TLSAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f TLSFinding) bool { return !f.Blocking && f.Reason != tlsReasonOK })
}

func (a TLSAudit) Describe() string {
	return describeTaggedFindings("TLS 配置未发现风险", a.Findings, tlsReasonOK, "tls", tlsMaxFindings,
		func(f TLSFinding) string { return f.Reason },
		func(f TLSFinding) string { return f.Key },
		func(f TLSFinding) string { return f.Detail })
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
