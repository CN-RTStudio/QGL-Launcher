package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func isReclaimableMetaName(name string) (base string, ok bool) {
	if len(name) <= len(reclaimedMetaSuffix) {
		return "", false
	}
	if name[len(name)-len(reclaimedMetaSuffix):] != reclaimedMetaSuffix {
		return "", false
	}
	base = name[:len(name)-len(reclaimedMetaSuffix)]
	if base == "" || base == "." {
		return "", false
	}
	return base, true
}

// isNativeTempName 区分 natives 解压临时文件（.native-*.tmp）。
func isNativeTempName(name string) bool {
	return isReclaimableTempName(name) && name[:len(reclaimedNativePrefix)] == reclaimedNativePrefix
}

// reclaimCandidateInput 是纯判定函数的输入，把文件系统细节隔离在外便于单测。
type reclaimCandidateInput struct {
	Name       string
	WithinRoot bool   // 已解析符号链接后是否仍严格位于根目录内
	IsSymlink  bool   // 该条目或其任一祖先是否为符号链接
	IsRegular  bool   // 是否普通文件
	Mtime      time.Time
	Size       int64
	BaseExists bool   // 仅对 .qglmeta：同目录基础文件是否存在
	Now        time.Time
}

// decideReclaimCandidate 是不碰文件系统的纯判定：返回（是否纳入, 类型, 跳过原因）。
// 三个返回值约定：纳入时 kind 有效、reason 为空；否则 ok=false、kind=""、reason 给码。
func decideReclaimCandidate(in reclaimCandidateInput) (ok bool, kind ReclaimKind, reason string) {
	if in.IsSymlink {
		return false, "", reclaimSkipSymlink
	}
	if !in.WithinRoot {
		return false, "", reclaimSkipNotInRoot
	}
	if !in.IsRegular {
		return false, "", reclaimSkipIrregular
	}
	if in.Now.Sub(in.Mtime) < reclaimerMinAge {
		return false, "", reclaimSkipTooYoung
	}
	if isReclaimableTempName(in.Name) {
		return true, reclaimKindTemp, ""
	}
	if base, metaOK := isReclaimableMetaName(in.Name); metaOK {
		_ = base
		// 基础文件还在：侧车是有效元数据，绝不能删。
		if in.BaseExists {
			return false, "", reclaimSkipMetaAlive
		}
		return true, reclaimKindOrphanMeta, ""
	}
	return false, "", reclaimSkipNotWhiteList
}

// assessReclaimBudget 在纳入一个候选前判断数量 / 字节预算是否还允许。
// 传入当前计划计数，返回是否允许纳入以及命中后是否恰好到顶。
func assessReclaimBudget(currentCount int, currentBytes, addBytes, maxBytes int64) (allow bool) {
	if currentCount >= reclaimerMaxFiles {
		return false
	}
	if maxBytes > 0 && currentBytes > maxBytes-addBytes {
		return false
	}
	return true
}

// pathResolvesWithinRoot 报告 target 在解析符号链接后是否仍严格位于 root 之内。
// root 与 target 都应为已 Clean 的绝对路径。target==root 也算在内部（用于根本身），
// 但调用方只会对“根下的文件”调用，文件不可能等于根。
func pathResolvesWithinRoot(root, target string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	if real, err := filepath.EvalSymlinks(targetAbs); err == nil {
		targetAbs = real
	}
	if real, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = real
	}
	if targetAbs == rootAbs {
		return true
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	return rel != ".." && !startsWithParentSegment(rel)
}

// startsWithParentSegment 判断相对路径是否以 "../" 开头（逃逸根目录）。
func startsWithParentSegment(rel string) bool {
	return len(rel) >= 3 && rel[0] == '.' && rel[1] == '.' && rel[2] == '/'
}

// planReclaimRoot 扫描单个根目录，把满足全部条件的残留文件纳入计划。
// 递归受深度 / 条目预算限制；任何符号链接目录不下钻，避免被引出根或陷入链接环。
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
