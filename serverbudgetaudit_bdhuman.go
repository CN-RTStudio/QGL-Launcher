package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func bdHuman(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit && exp < 3; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGT"[exp])
}

type bdWalkState struct {
	bytes     int64
	entries   int
	files     int
	dirs      int
	links     int
	truncated bool
}

func bdWalk(root string, maxDepth int) bdWalkState {
	state := bdWalkState{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if state.entries >= bdMaxEntries {
			state.truncated = true
			return filepath.SkipAll
		}
		state.entries++
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && rel != "." {
			depth := strings.Count(rel, string(os.PathSeparator))
			if depth > maxDepth {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			state.links++
			return nil
		}
		if info.IsDir() {
			state.dirs++
			return nil
		}
		if info.Mode().IsRegular() {
			state.files++
			state.bytes += info.Size()
		}
		return nil
	})
	return state
}

func bdCountFiles(dir string, limit int) (int, int64) {
	count := 0
	var total int64
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, entry := range entries {
		if count >= limit {
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		count++
		if info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return count, total
}
