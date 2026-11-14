package main

import ()

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
