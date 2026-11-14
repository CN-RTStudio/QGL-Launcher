package main

import (
	"sort"
)

func (audit RegionAudit) HasWarnings() bool {
	return len(audit.Findings) > 0 && !audit.Blocking()
}

func (audit RegionAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, finding := range audit.Findings {
		if !seen[finding.Reason] {
			seen[finding.Reason] = true
			codes = append(codes, finding.Reason)
		}
	}
	sort.Strings(codes)
	return codes
}
