package main

import (
	"strings"
)

func sanitizeAuditDetail(detail string) string {
	s := sanitizeLogLine(detail)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	s = strings.TrimSpace(b.String())
	runes := []rune(s)
	if len(runes) > auditMaxDetailRunes {
		s = string(runes[:auditMaxDetailRunes]) + "…"
	}
	return s
}

func validAuditCategory(c string) bool {
	switch c {
	case auditCategoryZip, auditCategoryExternalURL, auditCategoryJVMEnv,
		auditCategoryInstaller, auditCategoryPrivateWrite, auditCategoryHashVerify,
		auditCategoryRateLimit, auditCategoryPermission, auditCategoryJarScan,
		auditCategoryLog4Shell, auditCategoryConsole, auditCategoryConfig,
		auditCategoryReclaim:
		return true
	}
	return false
}

func validAuditSeverity(v string) bool {
	return v == auditSeverityInfo || v == auditSeverityWarn || v == auditSeverityCritical
}

func validAuditAction(a string) bool {
	return a == auditActionBlocked || a == auditActionRejected ||
		a == auditActionStripped || a == auditActionRepeated || a == auditActionDetected
}
