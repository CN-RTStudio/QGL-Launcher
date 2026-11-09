package main

import (
	"os"
	"path/filepath"
	"strings"
)

func resolveManagedModPath(mcDir, p string) (string, bool) {
	// 预检原始文件名段（尚未经过 Windows 路径归一化）：尾部点 / 空格 / 控制字符等
	// 会被 OS 层 Abs/Clean 静默剥离或折叠，导致 "a.jar " 归一化后冒充合法受管文件。
	// 这里在归一化之前就用 modNameLooksSafe 拦截，保持与 modNameLooksSafe 的
	// “Win32 会吞掉的点 / 空格结尾一律不受管”口径一致。
	rawBase := p
	if trimmed := strings.TrimRight(p, `\/`); trimmed != "" {
		rawBase = filepath.Base(trimmed)
	}
	if !modNameLooksSafe(rawBase) {
		return "", false
	}

	root, err := canonicalAbs(mcDir)
	if err != nil {
		return "", false
	}
	abs, err := canonicalAbs(p)
	if err != nil {
		return "", false
	}
	// 先做整体归属：任何落在 .minecraft 之外（盘符逃逸 / Clean 后仍越界）的直接拒绝。
	if !PathWithinRoot(abs, root) {
		return "", false
	}
	if abs == root {
		return "", false
	}
	rel := abs[len(root)+1:]
	segs := strings.Split(rel, string(os.PathSeparator))

	var fileName string
	switch {
	case len(segs) == 2 && strings.EqualFold(segs[0], modsDirSegment):
		// 全局 mods 目录顶层文件。
		fileName = segs[1]
	case len(segs) == 4 && strings.EqualFold(segs[0], versionsSegment) &&
		strings.EqualFold(segs[2], modsDirSegment) && safeVersionSegment(segs[1]):
		// 版本隔离 mods 目录；版本段必须是真实单段名（Clean 已折叠 ".."，
		// safeVersionSegment 再排除空段 / "." / 分隔符），防止 versions/../mods 触底。
		fileName = segs[3]
	default:
		return "", false
	}

	if !isModJarName(fileName) {
		return "", false
	}
	return abs, true
}
