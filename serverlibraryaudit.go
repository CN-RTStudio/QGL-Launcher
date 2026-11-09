package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	libReasonOK               = "ok"
	libReasonMissing          = "missing"
	libReasonUnreadable       = "unreadable"
	libReasonTooLarge         = "too-large"
	libReasonSymlink          = "symlink"
	libReasonTooMany          = "too-many"
	libReasonNotAJar          = "not-a-jar"
	libReasonDuplicateVersion = "duplicate-version"
	libReasonShadowCopy       = "shadow-copy"
	libReasonBadName          = "bad-name"
	libReasonWorldWritable    = "world-writable"

	libMaxFileBytes = 256 << 20
	libMaxFiles     = 512
	libMaxDepth     = 6
	libMaxFindings  = 96
)

var libRoots = []string{"libs", "libraries"}

type LibraryFinding = auditFinding

type LibraryAudit struct {
	Dir      string
	Jars     []string
	Findings []LibraryFinding
}

func (a LibraryAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f LibraryFinding) bool { return f.Blocking })
}

func (a LibraryAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f LibraryFinding) bool { return !f.Blocking && f.Reason != libReasonOK })
}

func (a LibraryAudit) Codes() []string {
	return findingCodesSkip(a.Findings, libReasonOK, func(f LibraryFinding) string { return f.Reason })
}

func (a LibraryAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现依赖库"
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

func (a LibraryAudit) Summary() string {
	blocking, warnings := auditTally(a.Findings, func(f LibraryFinding) bool { return f.Blocking }, func(f LibraryFinding) bool { return !f.Blocking && f.Reason != libReasonOK })
	return fmt.Sprintf("jars=%d findings=%d blocking=%d warnings=%d", len(a.Jars), len(a.Findings), blocking, warnings)
}

func (a *LibraryAudit) add(file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, libMaxFindings, LibraryFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func libArtifactKey(name string) string {
	lower := strings.ToLower(strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)))
	for _, marker := range []string{"-sources", "-javadoc", "-natives"} {
		lower = strings.TrimSuffix(lower, marker)
	}
	segments := strings.Split(lower, "-")
	kept := []string{}
	for _, segment := range segments {
		if segment == "" || libLooksVersion(segment) {
			continue
		}
		kept = append(kept, segment)
	}
	if len(kept) == 0 {
		return lower
	}
	return strings.Join(kept, "-")
}
