package main

import (
	"io/fs"
	"os"
	"time"
)

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
