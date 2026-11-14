package main

import (
	"path/filepath"
	"strings"
)

func (g *GameClasspathAudit) FirstCriticalCode() string {
	for _, f := range g.Findings {
		if f.Severity == launchSeverityCritical {
			return f.Code
		}
	}
	return ""
}

// classifyGameClasspathEntry 判定单条 classpath 条目的安全性。返回 "" 表示安全，否则
// 返回稳定错误 code。roots 为允许的根集合（通常是 .minecraft）。
func classifyGameClasspathEntry(entry string, roots []string) string {
	if entry == "" {
		return "gcp-empty"
	}
	if len(entry) > maxPathLen {
		return "gcp-long"
	}
	if containsControlByte(entry) {
		return "gcp-control"
	}
	if isUNC(entry) {
		return "gcp-unc"
	}
	if !filepath.IsAbs(entry) {
		return "gcp-not-absolute"
	}
	if hasTraversalSegment(entry) {
		return "gcp-traversal"
	}
	if !strings.EqualFold(filepath.Ext(entry), ".jar") {
		return "gcp-not-jar"
	}
	if !containedInAnyRoot(entry, roots) {
		return "gcp-outside-root"
	}
	return ""
}
