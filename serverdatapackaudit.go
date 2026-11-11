package main

import (
	"path/filepath"
)

const (
	dpReasonOK             = "ok"
	dpReasonMissing        = "missing"
	dpReasonUnreadable     = "unreadable"
	dpReasonTooLarge       = "too-large"
	dpReasonSymlink        = "symlink"
	dpReasonTooMany        = "too-many"
	dpReasonBadZip         = "bad-zip"
	dpReasonEntryEscape    = "entry-escape"
	dpReasonDuplicateName  = "duplicate-entry"
	dpReasonMissingMcmeta  = "missing-mcmeta"
	dpReasonInvalidMcmeta  = "invalid-mcmeta"
	dpReasonBadDescription = "bad-description"
	dpReasonEmptyPack      = "empty-pack"

	dpMaxFileBytes = 64 << 20
	dpMaxEntries   = 8192
	dpMaxPacks     = 32
	dpMaxFindings  = 96
	dpMaxDescLen   = 256
)

var dpRoots = []string{"datapacks", filepath.Join("world", "datapacks")}

type DataPackFinding = auditFinding

type DataPackAudit struct {
	Dir      string
	Packs    []string
	Findings []DataPackFinding
}

func (a DataPackAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f DataPackFinding) bool { return f.Blocking })
}

func (a DataPackAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f DataPackFinding) bool { return !f.Blocking && f.Reason != dpReasonOK })
}

func (a DataPackAudit) Codes() []string {
	return findingCodesSkip(a.Findings, dpReasonOK, func(f DataPackFinding) string { return f.Reason })
}
