package main

import ()

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

func libLooksVersion(segment string) bool {
	digits, alpha := 0, 0
	for i := 0; i < len(segment); i++ {
		ch := segment[i]
		if ch >= '0' && ch <= '9' {
			digits++
			continue
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			alpha++
		}
	}
	if digits == 0 {
		return false
	}
	return digits >= alpha
}
