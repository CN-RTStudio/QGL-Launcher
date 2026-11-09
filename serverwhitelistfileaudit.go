package main

import (
	"strings"
)

const (
	swfMaxFindings = 32
	swfMaxFile     = 512 * 1024
	swfMaxEntries  = 512
	swfReasonMiss  = "missing"
	swfReasonLink  = "symlink"
	swfReasonLarge = "too-large"
	swfReasonRead  = "unreadable"
	swfReasonShape = "invalid-shape"
	swfReasonMany  = "too-many-entries"
	swfReasonUUID  = "invalid-uuid"
	swfReasonName  = "invalid-name"
	swfReasonCtl   = "control-characters"
	swfReasonDup   = "duplicate-entry"
	swfReasonEmpty = "empty-whitelist"
)

type WhitelistFileFinding = auditFinding

type WhitelistFileAudit struct {
	ServerDir string
	Findings  []WhitelistFileFinding
}

type whitelistFileEntry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

func (a *WhitelistFileAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, swfMaxFindings, WhitelistFileFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WhitelistFileAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WhitelistFileFinding) bool { return f.Blocking })
}

func (a *WhitelistFileAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WhitelistFileAudit) Describe() string {
	return describeFileReasonDetail("服务器白名单文件未发现风险", a.Findings, 12)
}

func swfValidUUID(value string) bool {
	clean := strings.ReplaceAll(value, "-", "")
	if len(clean) != 32 {
		return false
	}
	for _, c := range clean {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func swfValidName(value string) bool {
	return propsValidName(value)
}
