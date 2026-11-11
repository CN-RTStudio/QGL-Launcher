package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"unicode/utf8"
)

func validateAccessIP(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 ip 字段"
	}
	if len(value) > 64 {
		return accessReasonBadEntry, "ip 字段长度超限"
	}
	if net.ParseIP(value) == nil {
		return accessReasonBadEntry, "ip 字段不是合法地址"
	}
	return "", ""
}

func validateAccessUUID(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 uuid 字段"
	}
	normalized := normalizeAccessUUID(value)
	if len(normalized) != 32 || !IsLowerHex(normalized, 32) {
		return accessReasonBadEntry, "uuid 不是 32 位十六进制"
	}
	return "", ""
}

func normalizeAccessUUID(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.ReplaceAll(value, "-", "")
	return value
}

func validateAccessName(raw string) (string, string) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return accessReasonBadEntry, "缺少 name 字段"
	}
	if utf8.RuneCountInString(value) > accessMaxNameRunes {
		return accessReasonBadEntry, fmt.Sprintf("name 超过 %d 字符", accessMaxNameRunes)
	}
	if containsControlByte(value) {
		return accessReasonBadEntry, "name 含控制字符"
	}
	if strings.ContainsAny(value, "/\\:\"'") {
		return accessReasonBadEntry, "name 含路径或引号字符"
	}
	return "", ""
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
