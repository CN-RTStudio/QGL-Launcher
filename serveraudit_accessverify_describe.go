package main

import (
	"fmt"
	"strings"
)

func (a ServerAccessAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "服务器权限文件未发现异常"
	}
	parts := make([]string, 0, len(a.Findings))
	for _, finding := range a.Findings {
		if finding.Entry != "" {
			parts = append(parts, fmt.Sprintf("%s[%s]: %s", finding.File, finding.Entry, finding.Detail))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", finding.File, finding.Detail))
		}
	}
	return strings.Join(parts, "；")
}

func AuditServerAccess(serverDir string) (ServerAccessAudit, error) {
	audit := ServerAccessAudit{Dir: serverDir}
	for _, name := range accessFileNames {
		fileAudit, err := auditAccessFile(serverDir, name)
		if err != nil {
			return audit, err
		}
		audit.Files = append(audit.Files, fileAudit)
		audit.Findings = append(audit.Findings, fileAudit.Findings...)
	}
	return audit, nil
}

const (
	acReasonOK             = "ok"
	acReasonMissing        = "missing"
	acReasonUnreadable     = "unreadable"
	acReasonTooLarge       = "too-large"
	acReasonMalformed      = "malformed"
	acReasonSymlink        = "symlink"
	acReasonOfflineMode    = "offline-mode"
	acReasonOpTooHigh      = "op-level-too-high"
	acReasonWhitelistOff   = "whitelist-disabled"
	acReasonDuplicateEntry = "duplicate-entry"
	acReasonMissingField   = "missing-field"

	acMaxJSONBytes = 1 << 20
	acMaxEntries   = 4096
	acMaxFindings  = 64
)

type AccessControlFinding = auditFinding

type AccessControlAudit struct {
	Dir      string
	Sources  []string
	Findings []AccessControlFinding
}

func (a AccessControlAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AccessControlFinding) bool { return f.Blocking })
}

func (a AccessControlAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f AccessControlFinding) bool { return !f.Blocking && f.Reason != acReasonOK })
}
