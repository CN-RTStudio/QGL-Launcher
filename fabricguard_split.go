package main

import (
	"strconv"
	"strings"
)

func CompareFabricVersions(a, b string) int {
	pa := splitVersionSegments(a)
	pb := splitVersionSegments(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var na, nb int64
		if i < len(pa) {
			na, _ = strconv.ParseInt(pa[i], 10, 64)
		}
		if i < len(pb) {
			nb, _ = strconv.ParseInt(pb[i], 10, 64)
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

// splitVersionSegments 把主版本拆成数字段（去掉预发布后缀）。
func splitVersionSegments(v string) []string {
	if i := strings.LastIndexByte(v, '-'); i > 0 {
		v = v[:i]
	}
	return strings.Split(v, ".")
}
