package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != bdReasonOK {
			return true
		}
	}
	return false
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
	if len(a.Findings) >= bdMaxFindings {
		return
	}
	a.Findings = append(a.Findings, BudgetFinding{
		Area:     area,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
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

func bdWalk(root string, maxDepth int) bdWalkState {
	state := bdWalkState{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if state.entries >= bdMaxEntries {
			state.truncated = true
			return filepath.SkipAll
		}
		state.entries++
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && rel != "." {
			depth := strings.Count(rel, string(os.PathSeparator))
			if depth > maxDepth {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			state.links++
			return nil
		}
		if info.IsDir() {
			state.dirs++
			return nil
		}
		if info.Mode().IsRegular() {
			state.files++
			state.bytes += info.Size()
		}
		return nil
	})
	return state
}

func bdCountFiles(dir string, limit int) (int, int64) {
	count := 0
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if count >= limit {
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		count++
		if info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return count, total
}

func AuditServerBudget(serverDir string) BudgetAudit {
	audit := BudgetAudit{Dir: serverDir, Totals: map[string]int64{}}
	if info, err := os.Stat(serverDir); err != nil || !info.IsDir() {
		audit.add("server", bdReasonMissing, "服务器目录不可用", false)
		return audit
	}

	total := bdWalk(serverDir, bdMaxDepth)
	audit.Totals["server"] = total.bytes
	if total.truncated {
		audit.add("server", bdReasonEntryCap, "目录条目过多，统计已截断", false)
	}
	if total.bytes > bdMaxTotalBytes {
		audit.add("server", bdReasonTotalLarge, fmt.Sprintf("整目录占用 %s", bdHuman(total.bytes)), false)
	}

	for _, name := range bdWatchDirs {
		dir := filepath.Join(serverDir, name)
		info, err := os.Lstat(dir)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			audit.add(name, bdReasonWorldSymlink, "世界目录是符号链接", true)
			continue
		}
		if !info.IsDir() {
			continue
		}
		state := bdWalk(dir, bdMaxDepth)
		audit.Totals[name] = state.bytes
		if state.links > 0 {
			audit.add(name, bdReasonWorldSymlink, fmt.Sprintf("世界目录内包含 %d 个符号链接", state.links), true)
		}
		if state.bytes > bdMaxWorldBytes {
			audit.add(name, bdReasonWorldLarge, fmt.Sprintf("世界体积 %s", bdHuman(state.bytes)), false)
			continue
		}
		regionDir := filepath.Join(dir, "region")
		regionCount, regionBytes := bdCountFiles(regionDir, bdMaxEntries)
		if regionCount > 0 && regionBytes > 0 {
			avg := regionBytes / int64(regionCount)
			if avg > bdMaxRegionBytes {
				audit.add(name, bdReasonRegionLarge, fmt.Sprintf("区域文件平均 %s", bdHuman(avg)), false)
			}
		}
	}

	if count, bytes := bdCountFiles(filepath.Join(serverDir, "logs"), bdMaxEntries); bytes > bdMaxLogBytes {
		audit.add("logs", bdReasonLogLarge, fmt.Sprintf("日志合计 %s，共 %d 个文件", bdHuman(bytes), count), false)
	}

	if count, _ := bdCountFiles(filepath.Join(serverDir, "crash-reports"), bdMaxEntries); count > bdMaxCrashReports {
		audit.add("crash-reports", bdReasonCrashMany, fmt.Sprintf("崩溃报告累计 %d 份", count), false)
	}

	if count := bdCountDirEntries(filepath.Join(serverDir, "mods"), bdMaxMods*2, func(name string) bool {
		return strings.HasSuffix(strings.ToLower(name), ".jar")
	}); count > bdMaxMods {
		audit.add("mods", bdReasonModsMany, fmt.Sprintf("模组数量 %d", count), false)
	}

	if count := bdCountDirEntries(filepath.Join(serverDir, "datapacks"), bdMaxDatapacks*2, func(name string) bool {
		lower := strings.ToLower(name)
		return strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".jar")
	}); count > bdMaxDatapacks {
		audit.add("datapacks", bdReasonDatapacksMany, fmt.Sprintf("数据包数量 %d", count), false)
	}

	if len(audit.Findings) == 0 {
		audit.add("server", bdReasonOK, fmt.Sprintf("整目录占用 %s", bdHuman(total.bytes)), false)
	}
	return audit
}

func bdCountDirEntries(dir string, limit int, accept func(string) bool) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if count >= limit {
			break
		}
		if entry.IsDir() {
			continue
		}
		if accept == nil || accept(entry.Name()) {
			count++
		}
	}
	return count
}
