package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	regionReasonOK          = "ok"
	regionReasonSymlink     = "symlink"
	regionReasonNotRegular  = "not-regular"
	regionReasonTooLarge    = "too-large"
	regionReasonShortHeader = "short-header"
	regionReasonBadOffset   = "bad-offset"
	regionReasonOutOfRange  = "out-of-range"
	regionReasonBadLength   = "bad-length"
	regionReasonBadName     = "bad-name"
	regionReasonTooMany     = "too-many-files"
	regionHeaderBytes       = 8192
	regionSectorBytes       = 4096
	regionSlotCount         = 1024
	regionMaxFiles          = 1024
	regionMaxBytes          = int64(2) << 30
)

var regionNamePattern = regexp.MustCompile(`^r\.-?[0-9]+\.-?[0-9]+\.mca$`)

type RegionFinding struct {
	Region   string
	Chunk    int
	Reason   string
	Detail   string
	Blocking bool
}

type RegionAudit struct {
	WorldDir    string
	RegionDirs  int
	RegionFiles int
	Chunks      int
	Findings    []RegionFinding
}

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
