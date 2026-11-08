package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	iconReasonOK              = "ok"
	iconReasonMissing         = "missing"
	iconReasonUnreadable      = "unreadable"
	iconReasonTooLarge        = "too-large"
	iconReasonSymlink         = "symlink"
	iconReasonBadType         = "bad-type"
	iconReasonTruncated       = "truncated"
	iconReasonOversized       = "oversized"
	iconReasonNonstandardSize = "nonstandard-size"
	iconReasonBadChunk        = "bad-chunk"
	iconReasonTrailingData    = "trailing-data"
	iconReasonInflateBomb     = "inflate-bomb"
	iconReasonBadColorType    = "bad-color-type"

	iconMaxFileBytes = 512 << 10
	iconMaxDimension = 512
	iconMaxFindings  = 48
	iconInflateLimit = 2048
)

var iconCandidates = []string{"server-icon.png", filepath.Join("world", "icon.png")}

type IconFinding struct {
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type IconAudit struct {
	Dir      string
	Files    []string
	Findings []IconFinding
}

func (a IconAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f IconFinding) bool { return f.Blocking })
}

func (a IconAudit) HasWarnings() bool {
	for _, f := range a.Findings {
		if !f.Blocking && f.Reason != iconReasonOK {
			return true
		}
	}
	return false
}

func (a IconAudit) Codes() []string {
	seen := map[string]bool{}
	codes := []string{}
	for _, f := range a.Findings {
		if f.Reason == iconReasonOK || seen[f.Reason] {
			continue
		}
		seen[f.Reason] = true
		codes = append(codes, f.Reason)
	}
	sort.Strings(codes)
	return codes
}

func (a IconAudit) Describe() string {
	if len(a.Findings) == 0 {
		return "未发现服务器图标"
	}
	parts := []string{}
	for _, f := range a.Findings {
		where := f.File
		if where == "" {
			where = "server"
		}
		parts = append(parts, fmt.Sprintf("%s(%s)", where, f.Reason))
		if len(parts) >= 6 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(a.Findings)))
			break
		}
	}
	return strings.Join(parts, ", ")
}

func (a IconAudit) Summary() string {
	blocking := 0
	warnings := 0
	for _, f := range a.Findings {
		if f.Blocking {
			blocking++
		} else if f.Reason != iconReasonOK {
			warnings++
		}
	}
	return fmt.Sprintf("files=%d findings=%d blocking=%d warnings=%d", len(a.Files), len(a.Findings), blocking, warnings)
}

func (a *IconAudit) add(file, reason, detail string, blocking bool) {
	if len(a.Findings) >= iconMaxFindings {
		return
	}
	a.Findings = append(a.Findings, IconFinding{File: file, Reason: reason, Detail: detail, Blocking: blocking})
}
