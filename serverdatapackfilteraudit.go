package main

import (
	"fmt"
	"sort"
	"strings"
)

const (
	pfReasonOK              = "ok"
	pfReasonMissing         = "missing"
	pfReasonUnreadable      = "unreadable"
	pfReasonSymlink         = "symlink"
	pfReasonTooLarge        = "too-large"
	pfReasonWorldWritable   = "world-writable"
	pfReasonWorldReadable   = "world-readable"
	pfReasonTooManyPacks    = "too-many-packs"
	pfReasonTooManyFilters  = "too-many-filters"
	pfReasonFilterAll       = "filter-covers-all"
	pfReasonEmptyNamespace  = "empty-namespace"
	pfReasonPathEscape      = "path-escape"
	pfReasonBadPattern      = "bad-pattern"
	pfReasonDuplicateFilter = "duplicate-filter"
	pfReasonWeakFormat      = "weak-pack-format"
	pfReasonDescLong        = "description-too-long"
	pfReasonUnknownKey      = "unknown-filter-key"
	pfReasonMalformedJSON   = "malformed-json"
	pfReasonEntryCap        = "entry-cap"

	pfMaxFileBytes = 256 << 10
	pfMaxPacks     = 64
	pfMaxFilters   = 64
	pfMaxDescChars = 1024
	pfMaxFindings  = 48
)

var pfPackRoots = []string{
	"datapacks",
	"world/datapacks",
}

type PackFilterFinding struct {
	Root     string
	Pack     string
	Reason   string
	Detail   string
	Blocking bool
}

type PackFilterAudit struct {
	Dir      string
	Findings []PackFilterFinding
	Packs    int
}

func (a PackFilterAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f PackFilterFinding) bool { return f.Blocking })
}

func (a PackFilterAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f PackFilterFinding) bool { return !f.Blocking && f.Reason != pfReasonOK })
}

func (a PackFilterAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == pfReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s/%s:%s:%s", f.Root, f.Pack, f.Reason, f.Detail))
		if len(parts) >= pfMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "数据包过滤规则未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *PackFilterAudit) add(root, pack, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, pfMaxFindings, PackFilterFinding{Root: root, Pack: pack, Reason: reason, Detail: detail, Blocking: blocking})
}

func pfEscapePattern(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return true
	}
	if strings.Contains(trimmed, "..") {
		return true
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "\\") {
		return true
	}
	if strings.ContainsAny(trimmed, "\\\x00") {
		return true
	}
	return false
}
