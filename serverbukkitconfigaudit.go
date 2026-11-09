package main

import (
	"path/filepath"
	"strings"
)

const (
	sbcMaxFindings       = 36
	sbcMaxConfig         = 256 * 1024
	sbcReasonOK          = "ok"
	sbcReasonMissing     = "missing"
	sbcReasonSymlink     = "symlink"
	sbcReasonTooLarge    = "too-large"
	sbcReasonUnread      = "unreadable"
	sbcReasonEmpty       = "empty-config"
	sbcReasonThrottle    = "connection-throttle-disabled"
	sbcReasonThrottleBad = "connection-throttle-invalid"
	sbcReasonPath        = "path-escape"
	sbcReasonControl     = "control-characters"
	sbcReasonProfiling   = "plugin-profiling-enabled"
	sbcReasonSpawn       = "spawn-limit-too-high"
	sbcReasonChunkGC     = "chunk-gc-disabled"
)

type BukkitFinding = auditFinding

type BukkitAudit struct {
	ServerDir string
	Findings  []BukkitFinding
}

func (a *BukkitAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sbcMaxFindings, BukkitFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *BukkitAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BukkitFinding) bool { return f.Blocking })
}

func (a *BukkitAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *BukkitAudit) Describe() string {
	return describeFileReasonDetail("Bukkit 配置未发现风险", a.Findings, 12)
}

func sbcSafeRelative(value string) (bool, string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false, "路径为空"
	}
	if filepath.IsAbs(trimmed) || strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") {
		return false, "使用了绝对路径"
	}
	if strings.Contains(trimmed, "..") {
		return false, "包含越界片段"
	}
	if strings.ContainsAny(trimmed, "\\") {
		return false, "包含反斜杠"
	}
	if strings.ContainsRune(trimmed, ':') {
		return false, "包含盘符或协议分隔符"
	}
	return true, ""
}
