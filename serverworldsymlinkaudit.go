package main

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	sytMaxEntries  = 4000
	sytMaxDepth    = 6
	sytMaxFindings = 24
	sytMaxFile     = 8 * 1024 * 1024
	sytMissing     = "world-dir-missing"
	sytNotDir      = "world-dir-not-directory"
	sytLink        = "world-entry-symlink"
	sytSpecial     = "world-entry-special-file"
	sytEscape      = "world-link-escapes-root"
	sytTooDeep     = "world-entry-too-deep"
	sytTooMany     = "world-entry-limit"
	sytLockFile    = "world-lock-file-present"
	sytUnreadable  = "world-entry-unreadable"
)

type WorldSymlinkFinding struct {
	Path     string
	Reason   string
	Detail   string
	Blocking bool
}

type WorldSymlinkAudit struct {
	ServerDir string
	WorldDir  string
	Findings  []WorldSymlinkFinding
	Entries   int
}

func (a *WorldSymlinkAudit) add(path, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, sytMaxFindings, WorldSymlinkFinding{Path: path, Reason: reason, Detail: detail, Blocking: blocking})
}

func (a *WorldSymlinkAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldSymlinkFinding) bool { return f.Blocking })
}

func (a *WorldSymlinkAudit) HasWarnings() bool {
	return hasAny(a.Findings)
}

func (a *WorldSymlinkAudit) Describe() string {
	return describeAuditFindings("世界存档目录未发现符号链接风险", a.Findings, 12,
		func(f WorldSymlinkFinding) []string {
			return []string{f.Reason, f.Path}
		},
		func(f WorldSymlinkFinding) string {
			if f.Detail == "" {
				return f.Reason
			}
			return f.Reason + "(" + f.Detail + ")"
		})
}

func sytWithinRoot(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	rel = filepath.Clean(rel)
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}
