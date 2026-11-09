package main

import (
	"strings"
)

const (
	soaMaxFindings  = 32
	soaMaxFile      = 512 * 1024
	soaMaxOperators = 64
	soaMaxLevel     = 4
	soaBusyOps      = 8
	soaReasonMiss   = "missing"
	soaReasonLink   = "symlink"
	soaReasonLarge  = "too-large"
	soaReasonRead   = "unreadable"
	soaReasonShape  = "invalid-shape"
	soaReasonLargeN = "too-many-operators"
	soaReasonUUID   = "invalid-uuid"
	soaReasonName   = "invalid-name"
	soaReasonLevel  = "invalid-level"
	soaReasonBypass = "invalid-bypass-flag"
	soaReasonDup    = "duplicate-operator"
	soaReasonOwner  = "owner-level-operator"
	soaReasonBusy   = "many-privileged-operators"
	soaReasonEmpty  = "empty-operator-list"
)

type OpsJsonFinding = auditFinding

type OpsJsonAudit struct {
	ServerDir string
	Findings  []OpsJsonFinding
}

type opsJsonEntry struct {
	UUID                string `json:"uuid"`
	Name                string `json:"name"`
	Level               *int   `json:"level"`
	BypassesPlayerLimit *bool  `json:"bypassesPlayerLimit"`
}

func (a *OpsJsonAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, soaMaxFindings, OpsJsonFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *OpsJsonAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f OpsJsonFinding) bool { return f.Blocking })
}

func (a *OpsJsonAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *OpsJsonAudit) Describe() string {
	return describeFileReasonDetail("服务器操作员清单未发现风险", a.Findings, 12)
}

func soaValidUUID(value string) bool {
	if len(value) != 36 && len(value) != 32 {
		return false
	}
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

func soaValidName(value string) bool {
	return propsValidName(value)
}
