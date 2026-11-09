package main

import (
	"strings"
)

const (
	sunMaxFindings      = 36
	sunMaxProps         = 256 * 1024
	sunMaxYAML          = 512 * 1024
	sunReasonOK         = "ok"
	sunReasonMissing    = "missing"
	sunReasonSymlink    = "symlink"
	sunReasonTooLarge   = "too-large"
	sunReasonUnreadable = "unreadable"
	sunReasonBadValue   = "bad-value"
	sunReasonSecureOff  = "secure-profile-off"
	sunReasonUsername   = "username-validation-off"
	sunReasonPermGen    = "perm-gen-allowed"
	sunReasonToggle     = "unsupported-toggle-enabled"
)

type UnsafeToggleFinding = auditFinding

type UnsafeToggleAudit struct {
	ServerDir string
	Findings  []UnsafeToggleFinding
}

func (a *UnsafeToggleAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sunMaxFindings, UnsafeToggleFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *UnsafeToggleAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f UnsafeToggleFinding) bool { return f.Blocking })
}

func (a *UnsafeToggleAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *UnsafeToggleAudit) Describe() string {
	return describeFileReason("实验性开关未发现风险", a.Findings, 12)
}

func sunLoadText(a *UnsafeToggleAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func sunBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}

func sunToggleDetail(key string) string {
	trimmed := strings.TrimPrefix(key, "unsupported-settings.")
	return "已启用实验性开关 " + trimmed
}
