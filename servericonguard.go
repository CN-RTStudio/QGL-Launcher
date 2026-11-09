package main

import (
	"path/filepath"
)

const (
	iconReasonOK              = "ok"
	iconReasonMissing         = "missing"
	iconReasonUnreadable      = "unreadable"
	iconReasonTooLarge        = "too-large"
	iconReasonSymlink         = "symlink"
	iconReasonBadType         = "bad-type"
	iconReasonTruncated       = "truncated"
	iconReasonOversized       = "oversized"
	iconReasonNonstandardSize = "nonstandard-size"
	iconReasonBadChunk        = "bad-chunk"
	iconReasonTrailingData    = "trailing-data"
	iconReasonInflateBomb     = "inflate-bomb"
	iconReasonBadColorType    = "bad-color-type"

	iconMaxFileBytes = 512 << 10
	iconMaxDimension = 512
	iconMaxFindings  = 48
	iconInflateLimit = 2048
)

var iconCandidates = []string{"server-icon.png", filepath.Join("world", "icon.png")}

type IconFinding = auditFinding

type IconAudit struct {
	Dir      string
	Files    []string
	Findings []IconFinding
}

func (a IconAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f IconFinding) bool { return f.Blocking })
}
