package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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
