package main

import (
	"fmt"
	"strings"
)

func (a *ServerStraySecretAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StraySecretFinding) bool { return f.Blocking })
}

func (a *ServerStraySecretAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f StraySecretFinding) bool { return !f.Blocking && f.Reason != strayReasonOK })
}

func (a *ServerStraySecretAudit) Codes() []string {
	return findingCodes(a.Findings, func(f StraySecretFinding) string { return f.Reason })
}

func (a *ServerStraySecretAudit) Describe() string {
	if a == nil || len(a.Findings) == 0 {
		return "服务器目录凭据扫描: 未发现候选文件"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s %s(%s)", f.Path, f.Reason, f.Detail))
	}
	if len(parts) == 0 {
		return "服务器目录凭据扫描: 通过"
	}
	return strings.Join(parts, "; ")
}

func (a *ServerStraySecretAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f StraySecretFinding) bool { return f.Blocking }, func(f StraySecretFinding) bool { return !f.Blocking && f.Reason != strayReasonOK })
	return fmt.Sprintf("凭据扫描 %d 个候选，阻断 %d，告警 %d", len(a.Scanned), blocking, warnings)
}

func strayNameMatches(name string) bool {
	lower := strings.ToLower(name)
	if straySecretNames[lower] {
		return true
	}
	for _, suffix := range []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return strings.HasPrefix(lower, "id_") && !strings.HasSuffix(lower, ".pub")
}
