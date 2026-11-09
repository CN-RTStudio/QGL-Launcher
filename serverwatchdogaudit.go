package main

import (
	"strings"
)

const (
	spwMaxFindings      = 40
	spwMaxProps         = 256 * 1024
	spwMaxYAML          = 512 * 1024
	spwMinTimeout       = 60
	spwMaxTimeout       = 900
	spwReasonOK         = "ok"
	spwReasonMissing    = "missing"
	spwReasonSymlink    = "symlink"
	spwReasonTooLarge   = "too-large"
	spwReasonUnreadable = "unreadable"
	spwReasonDisabled   = "watchdog-disabled"
	spwReasonLow        = "watchdog-timeout-low"
	spwReasonHigh       = "watchdog-timeout-high"
	spwReasonBadValue   = "bad-value"
	spwReasonNoScript   = "restart-script-missing"
	spwReasonAbsPath    = "restart-script-absolute-path"
	spwReasonTraversal  = "restart-script-traversal"
	spwReasonMeta       = "restart-script-metacharacters"
	spwReasonEarlyOff   = "early-warning-disabled"
	spwReasonEarlyBad   = "early-warning-invalid"
	spwReasonRestartOff = "restart-on-crash-disabled"
)

type WatchdogFinding = auditFinding

type WatchdogAudit struct {
	ServerDir string
	Findings  []WatchdogFinding
}

func (a *WatchdogAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, spwMaxFindings, WatchdogFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WatchdogAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WatchdogFinding) bool { return f.Blocking })
}

func (a *WatchdogAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WatchdogAudit) Describe() string {
	return describeFileReason("看门狗与重启配置未发现风险", a.Findings, 12)
}

func spwLoadText(a *WatchdogAudit, root, rel string, maxBytes int64) (string, bool) {
	return loadServerText(root, rel, maxBytes, a.add)
}

func spwBool(flat map[string]string, path string) (bool, bool) {
	return flatBoolValue(flat, path)
}

func spwText(flat map[string]string, path string) (string, bool) {
	value, ok := cfgLookup(flat, path)
	if !ok {
		return "", false
	}
	return cfgStripQuotes(value), true
}

func spwScriptProblem(script string) (string, string) {
	trimmed := strings.TrimSpace(script)
	if trimmed == "" {
		return spwReasonNoScript, "restart-script 为空"
	}
	if strings.ContainsRune(trimmed, 0) || cfgHasControlChars(trimmed) {
		return spwReasonMeta, "restart-script 含控制字符"
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") || strings.Contains(trimmed, ":\\") {
		return spwReasonAbsPath, "restart-script 使用绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return spwReasonTraversal, "restart-script 含目录穿越片段"
	}
	if strings.ContainsAny(trimmed, ";&|`$><\n") {
		return spwReasonMeta, "restart-script 含 shell 元字符"
	}
	return "", ""
}
