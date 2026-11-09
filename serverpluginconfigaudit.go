package main

import (
	"fmt"
	"strings"
)

const (
	pcReasonOK              = "ok"
	pcReasonMissing         = "missing"
	pcReasonUnreadable      = "unreadable"
	pcReasonTooLarge        = "too-large"
	pcReasonSymlink         = "symlink"
	pcReasonTooMany         = "too-many"
	pcReasonDangerousToggle = "dangerous-toggle"
	pcReasonPlaintextSecret = "plaintext-secret"
	pcReasonWorldReadable   = "world-readable"
	pcReasonDepthExceeded   = "depth-exceeded"

	pcMaxFileBytes = 512 << 10
	pcMaxFiles     = 512
	pcMaxDepth     = 3
	pcMaxFindings  = 96
	pcMaxLineScan  = 4096
)

var pcConfigExts = []string{".yml", ".yaml", ".json", ".toml", ".conf", ".properties"}

var pcDangerousKeys = []string{
	"bypass-permissions",
	"bypass_permissions",
	"bypasspermissions",
	"allow-unsafe",
	"allow_unsafe",
	"allowunsafe",
	"allow-flight",
	"allow_flight",
	"allowflight",
	"debug",
	"disable-auth",
	"disable_auth",
	"disableauth",
	"skip-auth",
	"auth-bypass",
	"op-override",
}

var pcSecretKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"api-key",
	"apikey",
	"api_key",
	"access-key",
	"private-key",
	"rcon-password",
}

type PluginConfigFinding = auditFinding

type PluginConfigAudit struct {
	Dir      string
	Files    []string
	Findings []PluginConfigFinding
}

func (a PluginConfigAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginConfigFinding) bool { return f.Blocking })
}

func (a PluginConfigAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginConfigFinding) bool { return !f.Blocking && f.Reason != pcReasonOK })
}

func (a PluginConfigAudit) Codes() []string {
	return findingCodesSkip(a.Findings, pcReasonOK, func(f PluginConfigFinding) string { return f.Reason })
}

func (a PluginConfigAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现插件配置"
	}
	parts := []string{}
	for _, f := range a.Findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", f.File, f.Reason))
		if len(parts) >= 4 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a PluginConfigAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != pcReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *PluginConfigAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pcMaxFindings, PluginConfigFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
