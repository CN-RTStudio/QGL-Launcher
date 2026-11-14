package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

func startsWithParentSegment(rel string) bool {
	return len(rel) >= 3 && rel[0] == '.' && rel[1] == '.' && rel[2] == '/'
}

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
