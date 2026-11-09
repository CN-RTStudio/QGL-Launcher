package main

import (
	"fmt"
	"strings"
)

const (
	mpeMaxFindings      = 48
	mpeMaxJarBytes      = 512 * 1024 * 1024
	mpeMaxEntryBytes    = 256 * 1024 * 1024
	mpeMaxEntries       = 20000
	mpeMaxRatio         = 1000
	mpeRatioMinBytes    = 1024 * 1024
	mpeMaxNestedJars    = 8
	mpeMaxPlugins       = 256
	mpeReasonOK         = "ok"
	mpeReasonMissing    = "missing"
	mpeReasonSymlink    = "symlink"
	mpeReasonTooLarge   = "too-large"
	mpeReasonBadJar     = "bad-jar"
	mpeReasonTraversal  = "entry-traversal"
	mpeReasonDuplicate  = "duplicate-entry"
	mpeReasonEntryLarge = "entry-too-large"
	mpeReasonBomb       = "zip-bomb"
	mpeReasonEntryCount = "entry-overflow"
	mpeReasonNested     = "nested-jars"
	mpeReasonBadName    = "bad-jar-name"
)

type PluginJarEntryFinding = auditFinding

type PluginJarEntryAudit struct {
	ServerDir string
	Jars      int
	Findings  []PluginJarEntryFinding
}

func (a *PluginJarEntryAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, mpeMaxFindings, PluginJarEntryFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *PluginJarEntryAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PluginJarEntryFinding) bool { return f.Blocking })
}

func (a *PluginJarEntryAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PluginJarEntryFinding) bool { return f.Reason != mpeReasonOK && !f.Blocking })
}

func (a *PluginJarEntryAudit) Describe() string {
	return describeFindings(a.Findings, func(f PluginJarEntryFinding) string { return fmt.Sprintf("%s:%s:%s", f.File, f.Reason, f.Detail) }, 12)
}

func mpeEntryUnsafe(name string) bool {
	if name == "" {
		return true
	}
	if strings.ContainsAny(name, "\x00\n\r") {
		return true
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "../") || strings.Contains(lower, "..\\") {
		return true
	}
	if strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
		return true
	}
	if len(name) > 1 && name[1] == ':' {
		return true
	}
	if strings.Contains(name, "\\") {
		return true
	}
	trimmed := strings.TrimPrefix(lower, "./")
	if strings.HasPrefix(trimmed, "../") {
		return true
	}
	return false
}
