package main

import (
	"strings"
)

func smnValidNode(node string) bool {
	if node == "" || len(node) > 128 {
		return false
	}
	if strings.HasPrefix(node, ".") || strings.HasSuffix(node, ".") {
		return false
	}
	if strings.Contains(node, "..") || strings.Contains(node, " ") {
		return false
	}
	for _, r := range node {
		if r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}
