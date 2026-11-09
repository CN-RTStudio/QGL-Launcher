package main

import (
	"os"
	"path/filepath"
)

func resolvedInside(rootAbs, p string) bool {
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		rootReal = rootAbs // root 尚不存在时退化为词法根
	}
	rootReal, _ = filepath.Abs(rootReal)

	if real, err := filepath.EvalSymlinks(p); err == nil {
		return lexicallyWithin(rootReal, real)
	}

	// p（或其某一级祖先）不存在：定位最长的已存在祖先。
	existing := p
	for {
		if _, statErr := os.Lstat(existing); statErr == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break // 已到卷根，无法再向上
		}
		existing = parent
	}

	realExisting, err := filepath.EvalSymlinks(existing)
	if err != nil {
		realExisting = existing
	}
	suffix, err := filepath.Rel(existing, p)
	if err != nil {
		return false
	}
	rebuilt, err := filepath.Abs(filepath.Join(realExisting, suffix))
	if err != nil {
		return false
	}
	return lexicallyWithin(rootReal, rebuilt)
}
