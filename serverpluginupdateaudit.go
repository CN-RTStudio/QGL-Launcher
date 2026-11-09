package main

import (
	"fmt"
)

const (
	spuMaxFindings    = 48
	spuReasonOK       = "ok"
	spuReasonMissing  = "missing"
	spuReasonAuto     = "auto-update-enabled"
	spuReasonInsecure = "update-source-insecure"
	spuReasonCreds    = "update-source-credentials"
	spuReasonPath     = "update-source-path-shape"
	spuReasonNoSource = "update-without-source"
	spuReasonChannel  = "update-channel-unstable"
	spuReasonBadValue = "bad-value"
	spuReasonScanNote = "scan"
)

type PluginUpdateFinding = auditFinding

type PluginUpdateAudit struct {
	ServerDir   string
	ConfigCount int
	Findings    []PluginUpdateFinding
}

func (a *PluginUpdateAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spuMaxFindings, PluginUpdateFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PluginUpdateAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginUpdateFinding) bool { return f.Blocking })
}

func (a *PluginUpdateAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginUpdateFinding) bool {
		return f.Reason != spuReasonOK && f.Reason != spuReasonScanNote && !f.Blocking
	})
}

func (a *PluginUpdateAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginUpdateFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func spuAutoUpdateKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"auto-update", "auto_update", "update-check", "update_check",
		"check-for-updates", "check_for_updates", "update-on-start",
	})
}

func spuSourceKeys(flat map[string]string) []string {
	return spxKeysWithSuffix(flat, []string{
		"update-url", "update_url", "download-url", "download_url",
		"update-check-url", "update_check_url", "update-repository", "repository-url",
	})
}
