package main

const (
	pfReasonOK              = "ok"
	pfReasonMissing         = "missing"
	pfReasonUnreadable      = "unreadable"
	pfReasonSymlink         = "symlink"
	pfReasonTooLarge        = "too-large"
	pfReasonWorldWritable   = "world-writable"
	pfReasonWorldReadable   = "world-readable"
	pfReasonTooManyPacks    = "too-many-packs"
	pfReasonTooManyFilters  = "too-many-filters"
	pfReasonFilterAll       = "filter-covers-all"
	pfReasonEmptyNamespace  = "empty-namespace"
	pfReasonPathEscape      = "path-escape"
	pfReasonBadPattern      = "bad-pattern"
	pfReasonDuplicateFilter = "duplicate-filter"
	pfReasonWeakFormat      = "weak-pack-format"
	pfReasonDescLong        = "description-too-long"
	pfReasonUnknownKey      = "unknown-filter-key"
	pfReasonMalformedJSON   = "malformed-json"
	pfReasonEntryCap        = "entry-cap"

	pfMaxFileBytes = 256 << 10
	pfMaxPacks     = 64
	pfMaxFilters   = 64
	pfMaxDescChars = 1024
	pfMaxFindings  = 48
)

var pfPackRoots = []string{
	"datapacks",
	"world/datapacks",
}

type PackFilterFinding struct {
	Root     string
	Pack     string
	Reason   string
	Detail   string
	Blocking bool
}

type PackFilterAudit struct {
	Dir      string
	Findings []PackFilterFinding
	Packs    int
}
