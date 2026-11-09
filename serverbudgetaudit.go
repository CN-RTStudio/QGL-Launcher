package main

import (
	"fmt"
	"sort"
	"strings"
)

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

func (a BudgetAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f BudgetFinding) bool { return !f.Blocking && f.Reason != bdReasonOK })
}

func (a BudgetAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == bdReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.Area, f.Reason, f.Detail))
		if len(parts) >= bdMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器磁盘占用未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *BudgetAudit) add(area, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, bdMaxFindings, BudgetFinding{Area: area, Reason: reason, Detail: detail, Blocking: blocking})
}

func bdHuman(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGT"[exp])
}

type bdWalkState struct {
	bytes     int64
	entries   int
	files     int
	dirs      int
	links     int
	truncated bool
}
