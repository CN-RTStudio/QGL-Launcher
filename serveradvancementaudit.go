package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	adReasonOK              = "ok"
	adReasonMissing         = "missing"
	adReasonUnreadable      = "unreadable"
	adReasonSymlink         = "symlink"
	adReasonTooLarge        = "too-large"
	adReasonWorldWritable   = "world-writable"
	adReasonWorldReadable   = "world-readable"
	adReasonTooManyFiles    = "too-many-files"
	adReasonBadFileName     = "bad-file-name"
	adReasonMalformedJSON   = "malformed-json"
	adReasonDeepNesting     = "deep-nesting"
	adReasonDuplicateKey    = "duplicate-key"
	adReasonLootTraversal   = "loot-traversal"
	adReasonIconTraversal   = "icon-traversal"
	adReasonParentEscape    = "parent-escape"
	adReasonTooManyCriteria = "too-many-criteria"
	adReasonEmptyFile       = "empty-file"

	adMaxFileBytes = 2 << 20
	adMaxFiles     = 128
	adMaxDepth     = 32
	adMaxCriteria  = 64
	adMaxFindings  = 48
)

var adAdvancementDirs = []string{
	"world/advancements",
	"world_nether/advancements",
	"world_the_end/advancements",
}

var adFilePattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.json$`)

type AdvancementFinding struct {
	Dir      string
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type AdvancementAudit struct {
	Dir      string
	Findings []AdvancementFinding
	Files    int
}

func (a AdvancementAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f AdvancementFinding) bool { return f.Blocking })
}

func (a AdvancementAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f AdvancementFinding) bool { return !f.Blocking && f.Reason != adReasonOK })
}

func (a AdvancementAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == adReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.Dir, f.Reason, f.Detail))
		if len(parts) >= adMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器进度数据未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *AdvancementAudit) add(dir, file, reason, detail string, blocking bool) {
	if len(a.Findings) >= adMaxFindings {
		return
	}
	a.Findings = append(a.Findings, AdvancementFinding{
		Dir:      dir,
		File:     file,
		Reason:   reason,
		Detail:   detail,
		Blocking: blocking,
	})
}

func adJSONDepth(data []byte) int {
	return jsonMaxDepth(data)
}

func adDuplicateKeys(data []byte) []string {
	return jsonDuplicateKeys(data)
}
