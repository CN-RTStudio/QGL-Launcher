package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	stReasonOK            = "ok"
	stReasonMissing       = "missing"
	stReasonUnreadable    = "unreadable"
	stReasonSymlink       = "symlink"
	stReasonTooLarge      = "too-large"
	stReasonWorldWritable = "world-writable"
	stReasonWorldReadable = "world-readable"
	stReasonTooManyFiles  = "too-many-files"
	stReasonBadFileName   = "bad-file-name"
	stReasonMalformedJSON = "malformed-json"
	stReasonDeepNesting   = "deep-nesting"
	stReasonNotObject     = "not-object"
	stReasonDuplicateKey  = "duplicate-key"
	stReasonTotalBytes    = "total-bytes"
	stReasonEntryCap      = "entry-cap"

	stMaxFileBytes  = 2 << 20
	stMaxTotalBytes = 64 << 20
	stMaxFiles      = 128
	stMaxDepth      = 32
	stMaxFindings   = 48
)

var stStatDirs = []string{
	"world/stats",
	"world_nether/stats",
	"world_the_end/stats",
}

var stFilePattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.json$`)

type StatsFinding struct {
	Dir      string
	File     string
	Reason   string
	Detail   string
	Blocking bool
}

type StatsAudit struct {
	Dir      string
	Findings []StatsFinding
	Files    int
	Bytes    int64
}

func (a StatsAudit) Blocking() bool {
	return anyBlocking(a.Findings, func(f StatsFinding) bool { return f.Blocking })
}

func (a StatsAudit) HasWarnings() bool {
	return auditHasWarning(a.Findings, func(f StatsFinding) bool { return !f.Blocking && f.Reason != stReasonOK })
}

func (a StatsAudit) Describe() string {
	parts := []string{}
	for _, f := range a.Findings {
		if f.Reason == stReasonOK {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%s:%s", f.Dir, f.Reason, f.Detail))
		if len(parts) >= stMaxFindings {
			break
		}
	}
	if len(parts) == 0 {
		return "服务器统计数据未发现异常"
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

func (a *StatsAudit) add(dir, file, reason, detail string, blocking bool) {
	a.Findings = appendAuditFinding(a.Findings, stMaxFindings, StatsFinding{Dir: dir, File: file, Reason: reason, Detail: detail, Blocking: blocking})
}

func stJSONDepth(data []byte) int {
	return jsonMaxDepth(data)
}

func stDuplicateKeys(data []byte) []string {
	return jsonDuplicateKeys(data)
}
