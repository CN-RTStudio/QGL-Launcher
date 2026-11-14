package main

import (
	"strings"
)

func spgWorldProblem(name string) bool {
	if name == "" {
		return true
	}
	if cfgHasControlChars(name) {
		return true
	}
	if strings.ContainsAny(name, "/\\:") || strings.Contains(name, "..") {
		return true
	}
	return false
}
