package main

import (
	"path/filepath"
	"strings"
)

func archiveEntryPathInside(baseDir, entryName string) (string, bool) {
	name := strings.ReplaceAll(entryName, "\\", "/")
	if name == "" || strings.HasPrefix(name, "/") {
		return "", false
	}
	if strings.Contains(name, ":") {
		return "", false
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if p == ".." {
			return "", false
		}
	}
	dest := filepath.Join(baseDir, filepath.FromSlash(name))
	rel, err := filepath.Rel(baseDir, dest)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return dest, true
}

func (a *App) recordSecurityEventBlockedArchive(scene, baseDir, entryName string) {
	if a == nil {
		return
	}
	a.writeLog("拦截越界压缩条目（%s）: %q 目标根 %s", scene, entryName, baseDir)
}
