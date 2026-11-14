package main

import (
	"runtime"
	"strings"
)

func zipDuplicateKey(rel string) string {
	if runtime.GOOS == "windows" {
		return strings.ToLower(rel)
	}
	return rel
}

func secureDestUnder(root, dest string) bool {
	return PathWithinRoot(dest, root)
}
