package main

import (
	"fmt"
	"sort"
	"strings"
)

func (a WorldRegionAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f WorldRegionFinding) bool { return !f.Blocking && f.Reason != wrReasonOK })
}

func (a WorldRegionAudit) Describe() string {
	var parts []string
	for _, f := range a.Findings {
		if f.Reason == wrReasonOK {
			continue
		}
		label := f.Path
		if label == "" {
			label = "world"
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", label, f.Reason, f.Detail))
		if len(parts) >= wrMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "世界区域文件未发现风险"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *WorldRegionAudit) add(path, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, wrMaxFindings, WorldRegionFinding{Path: path, Reason: reason, Detail: detail, Blocking: blocking})
}

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
