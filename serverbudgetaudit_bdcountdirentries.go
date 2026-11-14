package main

import (
	"os"
)

func bdCountDirEntries(dir string, limit int, accept func(string) bool) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if count >= limit {
			break
		}
		if entry.IsDir() {
			continue
		}
		if accept == nil || accept(entry.Name()) {
			count++
		}
	}
	return count
}
