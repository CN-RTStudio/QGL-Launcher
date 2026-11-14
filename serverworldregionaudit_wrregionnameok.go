package main

import (
	"strings"
)

func wrRegionNameOK(name string) bool {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".mca") {
		return false
	}
	stem := strings.TrimSuffix(lower, ".mca")
	parts := strings.Split(stem, ".")
	if len(parts) != 3 || parts[0] != "r" {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" {
			return false
		}
		for _, r := range part {
			if (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}
