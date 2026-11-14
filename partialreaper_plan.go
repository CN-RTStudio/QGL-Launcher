package main

import (
	"path/filepath"
)

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
