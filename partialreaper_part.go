package main

import (
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
	WithinRoot bool // 已解析符号链接后是否仍严格位于根目录内
	IsSymlink  bool // 该条目或其任一祖先是否为符号链接
	IsRegular  bool // 是否普通文件
	Mtime      time.Time
	Size       int64
	BaseExists bool // 仅对 .qglmeta：同目录基础文件是否存在
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
