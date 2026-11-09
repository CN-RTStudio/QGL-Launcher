package main

import (
	"fmt"
	"sort"
	"strings"
)

func (audit RegionAudit) Blocking() bool {
	for _, finding := range audit.Findings {
		if finding.Blocking {
			return true
		}
	}
	return false
}

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

func (audit RegionAudit) Describe() string {
	if len(audit.Findings) == 0 {
		return "区域文件结构校验通过"
	}
	parts := make([]string, 0, len(audit.Findings))
	for _, finding := range audit.Findings {
		parts = append(parts, fmt.Sprintf("%s#%d(%s:%s)", finding.Region, finding.Chunk, finding.Reason, finding.Detail))
	}
	return strings.Join(parts, "；")
}
