package main

import (
	"strings"
)

const (
	spgMaxFindings      = 36
	spgMaxConfig        = 256 * 1024
	spgMaxRadius        = 8192
	spgWarnRadius       = 4096
	spgReasonOK         = "ok"
	spgReasonMissing    = "missing"
	spgReasonSymlink    = "symlink"
	spgReasonTooLarge   = "too-large"
	spgReasonUnreadable = "unreadable"
	spgReasonNoConfig   = "config-missing"
	spgReasonRadius     = "radius-invalid"
	spgReasonRadiusBig  = "radius-too-large"
	spgReasonWorld      = "world-name-invalid"
	spgReasonTasksPath  = "task-world-path"
	spgReasonBadValue   = "bad-value"
	spgReasonSilent     = "silent-progress-disabled"
)

type PregenFinding = auditFinding

type PregenAudit struct {
	ServerDir string
	Findings  []PregenFinding
}

func (a *PregenAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spgMaxFindings, PregenFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PregenAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PregenFinding) bool { return f.Blocking })
}

func (a *PregenAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *PregenAudit) Describe() string {
	return describeFileReason("区块预生成配置未发现风险", a.Findings, 12)
}

func spgLoadText(a *PregenAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spgText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}

func spgWorldProblem(name string) bool {
	if name == "" {
		return true
	}
	if cfgHasControlChars(name) {
		return true
	}
	if strings.ContainsAny(name, "/\\:") || strings.Contains(name, "..") {
		return true
	}
	return false
}
