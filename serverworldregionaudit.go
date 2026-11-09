package main

import "path/filepath"

const (
	wrReasonOK           = "ok"
	wrReasonMissing      = "missing"
	wrReasonUnreadable   = "unreadable"
	wrReasonSymlink      = "symlink"
	wrReasonTooLarge     = "too-large"
	wrReasonTooMany      = "too-many"
	wrReasonShadowRegion = "shadow-region"
	wrReasonUnknownDim   = "unknown-dimension"
	wrReasonSizeBudget   = "world-size-budget"
	wrReasonBadName      = "bad-region-name"

	wrMaxRegionBytes = 512 << 20
	wrMaxRegions     = 2048
	wrMaxWorldBytes  = 8 << 30
	wrMaxDims        = 8
	wrMaxFindings    = 48
)

var wrWorldCandidates = []string{
	"world",
	"world_nether",
	"world_the_end",
	filepath.Join("world", "DIM-1"),
	filepath.Join("world", "DIM1"),
}
var wrRegionDirs = []string{"region", "entities", "poi"}

type WorldRegionFinding struct {
	Path     string
	Reason   string
	Detail   string
	Blocking bool
}
type WorldRegionAudit struct {
	Dir      string
	Worlds   []string
	Regions  int
	Bytes    int64
	Findings []WorldRegionFinding
}

func (a WorldRegionAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldRegionFinding) bool { return f.Blocking })
}
