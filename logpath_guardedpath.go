package main

import (
	"path/filepath"
	"strings"
)

func pathWithinRoot(root, target string) bool {
	root = filepath.Clean(root)
	target = filepath.Clean(target)
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(rel)
}

func (a *App) guardedLogPath() (string, bool) {
	mcRoot := a.GetMinecraftDir()
	candidate := a.launchLogPath
	if candidate == "" {
		candidate = filepath.Join(mcRoot, "qgl_install.log")
	}
	candidate = filepath.Clean(candidate)
	if pathWithinRoot(mcRoot, candidate) {
		return candidate, true
	}
	fallback := filepath.Join(mcRoot, "qgl_install.log")
	if pathWithinRoot(mcRoot, fallback) {
		return fallback, true
	}
	return "", false
}
