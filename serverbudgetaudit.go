package main

const (
	bdReasonOK            = "ok"
	bdReasonMissing       = "missing"
	bdReasonWorldSymlink  = "world-symlink"
	bdReasonRegionLarge   = "region-file-large"
	bdReasonWorldLarge    = "world-large"
	bdReasonLogLarge      = "logs-large"
	bdReasonCrashMany     = "crash-reports-many"
	bdReasonModsMany      = "mods-many"
	bdReasonDatapacksMany = "datapacks-many"
	bdReasonTotalLarge    = "server-large"
	bdReasonEntryCap      = "walk-truncated"

	bdMaxDepth        = 6
	bdMaxEntries      = 20000
	bdMaxRegionBytes  = 256 << 20
	bdMaxWorldBytes   = 8 << 30
	bdMaxLogBytes     = 1 << 30
	bdMaxCrashReports = 20
	bdMaxMods         = 300
	bdMaxDatapacks    = 100
	bdMaxTotalBytes   = 16 << 30
	bdMaxFindings     = 48
)

var bdWatchDirs = []string{"world", "world_nether", "world_the_end"}

type BudgetFinding struct {
	Area     string
	Reason   string
	Detail   string
	Blocking bool
}

type BudgetAudit struct {
	Dir      string
	Findings []BudgetFinding
	Totals   map[string]int64
}

func (a BudgetAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f BudgetFinding) bool { return f.Blocking })
}
