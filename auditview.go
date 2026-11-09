package main

import "sort"

func auditHasWarning[F any](findings []F, warn func(F) bool) bool {
	for _, f := range findings {
		if warn(f) {
			return true
		}
	}
	return false
}

func findingCodesSkip[F any](findings []F, ok string, code func(F) string) []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range findings {
		c := code(f)
		if c == ok || seen[c] {
			continue
		}
		seen[c] = true
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}
