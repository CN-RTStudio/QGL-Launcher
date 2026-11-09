package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	wrReasonOK           = "ok"
	wrReasonMissing      = "missing"
	wrReasonUnreadable   = "unreadable"
	wrReasonSymlink      = "symlink"
	wrReasonTooLarge     = "too-large"
	wrReasonTooMany      = "too-many"
	wrReasonShadowRegion = "shadow-region"
	wrReasonUnknownDim   = "unknown-dimension"
	wrReasonSizeBudget   = "world-size-budget"
	wrReasonBadName      = "bad-region-name"

	wrMaxRegionBytes = 512 << 20
	wrMaxRegions     = 2048
	wrMaxWorldBytes  = 8 << 30
	wrMaxDims        = 8
	wrMaxFindings    = 48
)

var wrWorldCandidates = []string{
	"world",
	"world_nether",
	"world_the_end",
	filepath.Join("world", "DIM-1"),
	filepath.Join("world", "DIM1"),
}

var wrRegionDirs = []string{"region", "entities", "poi"}

type WorldRegionFinding struct {
	Path     string
	Reason   string
	Detail   string
	Blocking bool
}

type WorldRegionAudit struct {
	Dir      string
	Worlds   []string
	Regions  int
	Bytes    int64
	Findings []WorldRegionFinding
}

func (a WorldRegionAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f WorldRegionFinding) bool { return f.Blocking })
}

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
