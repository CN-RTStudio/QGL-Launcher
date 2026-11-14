package main

import (
	"os"
	"path/filepath"
	"strings"
)

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
