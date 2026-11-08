package main

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// reclaimservice.go —— 把 partialreaper 内核接到启动器：确定“允许扫哪些根目录”、
// 在启动后异步回收、并给前端暴露一个可手动触发的清理入口。
//
// 根目录采用白名单：回收器只在启动器自有缓存目录与 Minecraft 数据目录内工作，
// 绝不扫描整个磁盘或用户目录。两个根之外的任何文件即使名字命中也不会被删
// （内核在计划与执行两个阶段都做严格归属校验）。

// reclaimRoots 返回本次允许回收的全部根目录（已去重、仅保留存在的目录）。
func (a *App) reclaimRoots() []string {
	seen := map[string]bool{}
	roots := make([]string, 0, 4)
	add := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil || seen[abs] {
			return
		}
		seen[abs] = true
		if info, statErr := os.Stat(abs); statErr != nil || info == nil || !info.IsDir() {
			return
		}
		roots = append(roots, abs)
	}

	tempDir := os.Getenv("TEMP")
	if tempDir == "" {
		tempDir = os.Getenv("TMP")
	}
	if tempDir == "" {
		tempDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Local", "Temp")
	}
	// loader.go 的 qgl_cache（forge 安装器 / 依赖缓存）与其中的临时文件。
	add(filepath.Join(tempDir, "qgl_cache"))
	// 游戏数据目录：版本 / 库 / natives 解压产生的 *.tmp 与散落的孤儿 *.qglmeta。
	add(a.GetMinecraftDir())
	// 数据根也扫一遍，覆盖自定义 MinecraftDir 指向别处时 QGL 自身缓存目录里的残留。
	add(a.GetQGLDir())
	return roots
}

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
