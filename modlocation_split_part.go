package main

import (
	"os"
	"path/filepath"
	"strings"
)

func safeVersionSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	return !strings.ContainsAny(seg, `/\`)
}

// resolveManagedModsDir 判定 p 是否为某个“受管 mods 目录”本身（用于下载落盘目录
// 校验）。接受精确布局：
//
//	<mcDir>/mods                    -> segs = [mods]
//	<mcDir>/versions/<v>/mods       -> segs = [versions, v, mods]
//
// mods 目录的上级、libraries、saves、mcDir 根等一律拒绝：下载队列的保存目录只能由
// 程序按版本隔离策略决定，不能由渲染层指到 .minecraft 内任意位置投放 jar。
func resolveManagedModsDir(mcDir, p string) (string, bool) {
	root, err := canonicalAbs(mcDir)
	if err != nil {
		return "", false
	}
	abs, err := canonicalAbs(p)
	if err != nil {
		return "", false
	}
	if !PathWithinRoot(abs, root) || abs == root {
		return "", false
	}
	rel := abs[len(root)+1:]
	segs := strings.Split(rel, string(os.PathSeparator))

	switch {
	case len(segs) == 1 && strings.EqualFold(segs[0], modsDirSegment):
		return abs, true
	case len(segs) == 3 && strings.EqualFold(segs[0], versionsSegment) &&
		strings.EqualFold(segs[2], modsDirSegment) && safeVersionSegment(segs[1]):
		return abs, true
	default:
		return "", false
	}
}

// sameManagedModDir 报告 rename 的源与目标是否归一化后位于同一个受管 mods 目录，
// 防止借改名把 jar 移出 / 移入非受管目录（源、目标都必须是受管 jar，且父目录相同）。
func sameManagedModDir(fromAbs, toAbs string) bool {
	fromDir := filepath.Dir(fromAbs)
	toDir := filepath.Dir(toAbs)
	return fromDir == toDir
}
