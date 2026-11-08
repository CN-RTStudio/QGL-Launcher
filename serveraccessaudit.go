package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	accessReasonOK         = "ok"
	accessReasonSymlink    = "symlink"
	accessReasonNotRegular = "not-regular"
	accessReasonTooLarge   = "too-large"
	accessReasonMalformed  = "malformed"
	accessReasonTooMany    = "too-many"
	accessReasonBadEntry   = "bad-entry"
	accessReasonDuplicate  = "duplicate"
	accessMaxFileBytes     = 4 << 20
	accessMaxEntries       = 512
	accessMaxNameRunes     = 64
	accessMinOpsLevel      = 1
	accessMaxOpsLevel      = 4
)

var accessFileNames = []string{
	"ops.json",
	"whitelist.json",
	"banned-players.json",
	"banned-ips.json",
}

type AccessFinding struct {
	File     string
	Entry    string
	Reason   string
	Detail   string
	Blocking bool
}

type AccessFileAudit struct {
	Name     string
	Present  bool
	Symlink  bool
	Entries  int
	Findings []AccessFinding
}

type ServerAccessAudit struct {
	Dir      string
	Files    []AccessFileAudit
	Findings []AccessFinding
}

type accessRecord struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Level   int    `json:"level"`
	IP      string `json:"ip"`
	Expires string `json:"expires"`
}

func (a ServerAccessAudit) Blocking() bool {
	for _, finding := range a.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerAccessAudit) HasWarnings() bool {
	for _, finding := range a.Findings {
		if !finding.Blocking {
			return true
		}
	}
	return false
}

func (a ServerAccessAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, finding := range a.Findings {
		if seen[finding.Reason] {
			continue
		}
		seen[finding.Reason] = true
		codes = append(codes, finding.Reason)
	}
	sort.Strings(codes)
	return codes
}

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
