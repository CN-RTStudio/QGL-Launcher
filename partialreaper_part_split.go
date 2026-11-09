package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func planReclaimRoot(root string, now time.Time, plan *ReclaimPlan) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: root, Reason: reclaimSkipNotInRoot})
		return
	}
	if info, statErr := os.Stat(rootAbs); statErr != nil || info == nil {
		// 根目录不存在视为“没有可回收内容”，不算错误。
		return
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > reclaimerMaxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			plan.EntriesSeen++
			if plan.EntriesSeen > reclaimerMaxEntries {
				plan.BudgetHit = true
				return
			}
			full := filepath.Join(dir, entry.Name())

			// 符号链接（无论文件还是目录）一律不下钻、不删除：回收器永远不跟随链接。
			if entry.Type()&fs.ModeSymlink != 0 {
				plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reclaimSkipSymlink})
				continue
			}
			if entry.IsDir() {
				if !pathResolvesWithinRoot(rootAbs, full) {
					plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reclaimSkipNotInRoot})
					continue
				}
				walk(full, depth+1)
				continue
			}

			info, infoErr := entry.Info()
			in := reclaimCandidateInput{
				Name:       entry.Name(),
				WithinRoot: pathResolvesWithinRoot(rootAbs, full),
				IsSymlink:  false, // 已在上面拦截符号链接
				Now:        now,
			}
			if infoErr == nil && info != nil {
				in.IsRegular = info.Mode().IsRegular()
				in.Mtime = info.ModTime()
				in.Size = info.Size()
			}
			// 侧车需要“同目录基础文件是否存在”这一输入。
			if base, ok := isReclaimableMetaName(entry.Name()); ok {
				if _, bErr := os.Lstat(filepath.Join(dir, base)); bErr == nil {
					in.BaseExists = true
				}
			}

			ok, kind, reason := decideReclaimCandidate(in)
			if !ok {
				plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reason})
				continue
			}
			if !assessReclaimBudget(len(plan.Items), plan.Bytes, in.Size, reclaimerMaxBytes) {
				plan.BudgetHit = true
				plan.Skipped = append(plan.Skipped, ReclaimSkipped{Path: full, Reason: reclaimSkipBudget})
				return
			}
			plan.Items = append(plan.Items, ReclaimItem{Path: full, Kind: kind, Size: in.Size})
			plan.Bytes += in.Size
		}
	}
	walk(rootAbs, 0)
}

// BuildReclaimPlan 对一组根目录生成统一回收计划。根目录由调用方显式给出（只允许
// 传启动器自有的缓存 / 数据目录），回收器自己不猜测磁盘路径。
func BuildReclaimPlan(roots []string, now time.Time) ReclaimPlan {
	plan := ReclaimPlan{Roots: append([]string(nil), roots...)}
	for _, root := range roots {
		if plan.EntriesSeen > reclaimerMaxEntries || len(plan.Items) >= reclaimerMaxFiles ||
			plan.Bytes >= reclaimerMaxBytes {
			plan.BudgetHit = true
			break
		}
		planReclaimRoot(root, now, &plan)
	}
	return plan
}

// executeReclaimPlan 严格按计划点名删除，不重新判定、不扩展范围。删除失败只记录，
// 不中断后续条目。执行者必须确认计划来自 BuildReclaimPlan，而非外部传入。
func executeReclaimPlan(plan ReclaimPlan) ReclaimReport {
	report := ReclaimReport{
		EntriesSeen:  plan.EntriesSeen,
		SkippedCount: len(plan.Skipped),
	}
	for _, item := range plan.Items {
		// 最后一道归属闸：即便计划被异常构造，执行前再次确认文件在某个允许根内。
		within := false
		for _, root := range plan.Roots {
			if pathResolvesWithinRoot(root, item.Path) {
				within = true
				break
			}
		}
		if !within {
			report.Failed = append(report.Failed, ReclaimFailure{Path: item.Path, Error: reclaimSkipNotInRoot})
			continue
		}
		// 用 Lstat 而非 Remove 直接删：拒绝任何符号链接 / 目录，只删普通文件。
		info, err := os.Lstat(item.Path)
		if err != nil {
			continue // 文件已不存在等同回收完成，不计失败
		}
		if info.Mode()&fs.ModeSymlink != 0 || info.IsDir() {
			report.Failed = append(report.Failed, ReclaimFailure{Path: item.Path, Error: reclaimSkipIrregular})
			continue
		}
		if err := os.Remove(item.Path); err != nil {
			report.Failed = append(report.Failed, ReclaimFailure{Path: item.Path, Error: err.Error()})
			continue
		}
		report.Deleted++
		report.Bytes += item.Size
	}
	return report
}
