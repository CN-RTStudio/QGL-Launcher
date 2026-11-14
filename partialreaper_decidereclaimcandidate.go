package main

import ()

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
