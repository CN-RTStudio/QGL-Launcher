package main

import (
	"strconv"
	"time"
)

// ReclaimResiduals 供前端“清理下载残留”按钮调用：返回执行报告。
// 计划与执行全部在白名单根内完成，年龄阈值保证不碰在途文件。
func (a *App) ReclaimResiduals() ReclaimReport {
	roots := a.reclaimRoots()
	plan := BuildReclaimPlan(roots, time.Now())
	report := executeReclaimPlan(plan)
	if report.Deleted > 0 {
		recordSecurityEvent(auditCategoryReclaim, auditSeverityInfo, auditActionStripped,
			"ReclaimResiduals",
			"回收下载残留 "+strconv.Itoa(report.Deleted)+" 个文件，释放 "+FormatBytes(report.Bytes)+
				"（跳过 "+strconv.Itoa(report.SkippedCount)+" 项，失败 "+strconv.Itoa(len(report.Failed))+" 项）")
	}
	if len(report.Failed) > 0 {
		recordSecurityEvent(auditCategoryReclaim, auditSeverityWarn, auditActionBlocked,
			"ReclaimResiduals", "部分残留删除失败 "+strconv.Itoa(len(report.Failed))+" 项")
	}
	return report
}

// runStartupReclaim 在启动后回收一次残留。失败不影响启动；只在确实回收了内容时
// 写一条 info 审计。年龄阈值（6h）已经避开启动期正在进行的下载，无需额外延迟。
func (a *App) runStartupReclaim() {
	defer func() { _ = recover() }()
	roots := a.reclaimRoots()
	if len(roots) == 0 {
		return
	}
	plan := BuildReclaimPlan(roots, time.Now())
	if len(plan.Items) == 0 {
		return
	}
	report := executeReclaimPlan(plan)
	if report.Deleted > 0 {
		recordSecurityEvent(auditCategoryReclaim, auditSeverityInfo, auditActionStripped,
			"startup-reclaim",
			"启动时回收下载残留 "+strconv.Itoa(report.Deleted)+" 个文件，释放 "+FormatBytes(report.Bytes))
	}
}
